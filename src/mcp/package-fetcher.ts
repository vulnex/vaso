import { mkdir, readFile, readdir, access } from 'node:fs/promises';
import { join, basename, relative, extname } from 'node:path';
import { homedir } from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { isTestPath } from '../analyzers/test-paths.js';

const execFileAsync = promisify(execFile);

const DEFAULT_TIMEOUT_MS = 60_000;
const MAX_BUFFER = 16 * 1024 * 1024;
// Don't load an absurdly large entry file into memory for static analysis.
const MAX_SOURCE_BYTES = 2_000_000;

/**
 * Conservative registry-spec shape: `name` or `@scope/name`, optionally
 * `@version`. Rejects git URLs, file paths, tarball URLs, and anything with
 * shell-ish characters, so `npm pack` can never be pointed at a local folder
 * or remote git source by a hostile config — it only ever fetches a named
 * package from the configured registry.
 */
const REGISTRY_SPEC_RE =
  /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*(?:@[a-zA-Z0-9.~^*><=|\- ]+)?$/i;

/**
 * Runs an external command. Injectable so the resolution flow can be unit-tested
 * without touching the network or the real `npm`/`tar` binaries.
 */
export type CommandRunner = (
  cmd: string,
  args: string[],
  opts: { cwd?: string; timeout?: number },
) => Promise<{ stdout: string; stderr: string }>;

const defaultRunner: CommandRunner = async (cmd, args, opts) => {
  const { stdout, stderr } = await execFileAsync(cmd, args, {
    cwd: opts.cwd,
    timeout: opts.timeout ?? DEFAULT_TIMEOUT_MS,
    maxBuffer: MAX_BUFFER,
    encoding: 'utf-8',
  });
  return { stdout: String(stdout), stderr: String(stderr) };
};

export interface PackageFetchOptions {
  cacheDir?: string;
  timeoutMs?: number;
  runner?: CommandRunner;
}

export function defaultPackageCacheDir(): string {
  return join(homedir(), '.vaso', 'mcp-pkg-cache');
}

export function isRegistrySpec(spec: string): boolean {
  return REGISTRY_SPEC_RE.test(spec);
}

function sanitizeSpec(spec: string): string {
  return spec.replace(/[^a-zA-Z0-9._-]+/g, '_').slice(0, 120) || 'pkg';
}

/**
 * Download an npm package's tarball and return its main entry source.
 *
 * Download-only by construction: it shells out to `npm pack --ignore-scripts`
 * (which fetches the tarball without running the package's lifecycle scripts)
 * and the system `tar` to extract it — the scanned package is never executed,
 * preserving VASO's "never run scanned code" invariant. Results are cached
 * under `~/.vaso/mcp-pkg-cache/` and reused offline. Any failure (network,
 * missing binary, bad spec) degrades gracefully to `undefined`.
 */
/** Where a resolved package is extracted (its `package.json` is here once fetched). */
export function packageExtractDir(spec: string, cacheDir: string = defaultPackageCacheDir()): string {
  return join(cacheDir, sanitizeSpec(spec), 'package');
}

/**
 * Why a package's source could not be resolved: `npm` (or `tar`) isn't on
 * PATH, `npm pack` failed (unknown package, registry or network error — `code`
 * is npm's error code when it printed one), timed out, or the package holds no
 * JavaScript source to analyze.
 */
export type PackageFetchFailure =
  | { reason: 'npm-not-found' | 'tar-not-found' | 'timeout' | 'no-source' | 'invalid-spec' }
  | { reason: 'npm-failed'; code?: string };

export interface PackageFetchResult {
  source?: string;
  failure?: PackageFetchFailure;
}

/** A failed command as a failure reason — never npm's own text, which can quote a registry URL with credentials. */
function commandFailure(cmd: 'npm' | 'tar', err: unknown): PackageFetchFailure {
  const e = err as { code?: unknown; killed?: boolean; signal?: unknown; stderr?: unknown } | undefined;
  if (e?.code === 'ENOENT') return { reason: cmd === 'npm' ? 'npm-not-found' : 'tar-not-found' };
  if (e?.killed || e?.signal === 'SIGTERM') return { reason: 'timeout' };
  const code = /\bnpm (?:error|ERR!) code (E[A-Z0-9_]+)/.exec(String(e?.stderr ?? ''))?.[1];
  return { reason: 'npm-failed', ...(code ? { code } : {}) };
}

/** A failure as a short phrase for messages: `npm not found on PATH`. */
export function describeFetchFailure(failure: PackageFetchFailure): string {
  switch (failure.reason) {
    case 'npm-not-found': return 'npm not found on PATH';
    case 'tar-not-found': return 'tar not found on PATH';
    case 'timeout': return 'npm pack timed out';
    case 'no-source': return 'the package has no JavaScript source';
    case 'invalid-spec': return 'not a registry package name';
    case 'npm-failed': return `npm pack failed${failure.code ? ` (${failure.code})` : ''}`;
  }
}

/** The package's source, or undefined on any failure (see fetchNpmPackageSource for why). */
export async function resolveNpmPackageSource(
  spec: string,
  options: PackageFetchOptions = {},
): Promise<string | undefined> {
  return (await fetchNpmPackageSource(spec, options)).source;
}

/** resolveNpmPackageSource, saying why when there is no source. */
export async function fetchNpmPackageSource(
  spec: string,
  options: PackageFetchOptions = {},
): Promise<PackageFetchResult> {
  if (!isRegistrySpec(spec)) return { failure: { reason: 'invalid-spec' } };

  const cacheDir = options.cacheDir ?? defaultPackageCacheDir();
  const runner = options.runner ?? defaultRunner;
  const timeout = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  const pkgDir = join(cacheDir, sanitizeSpec(spec));
  const extractedDir = join(pkgDir, 'package'); // npm tarballs extract to package/

  // Cache hit: a previous run already extracted this exact spec.
  const cached = await collectPackageSource(extractedDir);
  if (cached) return { source: cached };

  try {
    await mkdir(pkgDir, { recursive: true });

    // 1) Download the tarball — no scripts, no deps, no execution.
    let stdout: string;
    try {
      ({ stdout } = await runner(
        'npm',
        ['pack', spec, '--json', '--ignore-scripts', '--pack-destination', pkgDir],
        { timeout },
      ));
    } catch (err) {
      return { failure: commandFailure('npm', err) };
    }
    const tarball = parsePackFilename(stdout);
    if (!tarball) return { failure: { reason: 'npm-failed' } };

    // 2) Extract locally with the system tar — still no execution.
    try {
      await runner('tar', ['-xzf', join(pkgDir, tarball), '-C', pkgDir], { timeout });
    } catch (err) {
      return { failure: commandFailure('tar', err) };
    }

    // 3) Collect the package's JS source.
    const source = await collectPackageSource(extractedDir);
    return source ? { source } : { failure: { reason: 'no-source' } };
  } catch {
    return { failure: { reason: 'npm-failed' } };
  }
}

export function parsePackFilename(stdout: string): string | undefined {
  try {
    const parsed = JSON.parse(stdout);
    // npm ≤ 11: `[{ filename, … }]`; npm 12: `{ "<name>": { filename, … } }`
    const entry = Array.isArray(parsed) ? parsed[0] : parsed && typeof parsed === 'object' ? Object.values(parsed)[0] : undefined;
    const filename = (entry as { filename?: unknown } | undefined)?.filename;
    if (filename) return basename(String(filename));
  } catch {
    const last = stdout
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean)
      .pop();
    if (last && last.endsWith('.tgz')) return basename(last);
  }
  return undefined;
}

const ENTRY_CANDIDATES = [
  'index.js',
  'dist/index.js',
  'build/index.js',
  'lib/index.js',
  'src/index.js',
  'index.mjs',
  'index.cjs',
  'main.js',
  'server.js',
];

async function findPackageEntry(dir: string): Promise<string | undefined> {
  try {
    const pkg = JSON.parse(await readFile(join(dir, 'package.json'), 'utf-8'));
    if (typeof pkg.main === 'string') {
      const p = join(dir, pkg.main);
      if (await exists(p)) return p;
    }
    if (pkg.bin) {
      const binEntry = typeof pkg.bin === 'string' ? pkg.bin : Object.values(pkg.bin)[0];
      if (binEntry) {
        const p = join(dir, String(binEntry));
        if (await exists(p)) return p;
      }
    }
  } catch {
    // no/invalid package.json — fall through to candidate scan
  }

  for (const candidate of ENTRY_CANDIDATES) {
    const p = join(dir, candidate);
    if (await exists(p)) return p;
  }
  return undefined;
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

const SOURCE_EXT = new Set(['.js', '.mjs', '.cjs']);
const SKIP_DIRS = new Set(['node_modules', 'test', 'tests', '__tests__', 'example', 'examples', '.git']);
const PER_FILE_CAP = 512 * 1024;

/**
 * Concatenate the package's JS source (main entry first, capped) rather than
 * just the `bin`/`main` file: real MCP servers are usually multi-file builds
 * whose entry is a thin shim, so the tool registrations and dangerous sinks
 * live in sibling modules. The AST analyzer parses with `errorRecovery`, so a
 * concatenation of several modules is safe to feed it.
 */
async function collectPackageSource(extractedDir: string): Promise<string | undefined> {
  const files = await listSourceFiles(extractedDir);
  if (files.length === 0) return undefined;

  // Order the declared entry first so single-file extractors see it first.
  const entry = await findPackageEntry(extractedDir);
  files.sort((a, b) => (a === entry ? -1 : b === entry ? 1 : a.localeCompare(b)));

  const parts: string[] = [];
  let total = 0;
  for (const file of files) {
    if (total >= MAX_SOURCE_BYTES) break;
    try {
      const buf = await readFile(file);
      const slice = buf.byteLength > PER_FILE_CAP ? buf.subarray(0, PER_FILE_CAP) : buf;
      parts.push(`// === ${relative(extractedDir, file)} ===\n${slice.toString('utf-8')}`);
      total += slice.byteLength;
    } catch {
      // unreadable file — skip
    }
  }
  return parts.length > 0 ? parts.join('\n\n') : undefined;
}

async function listSourceFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  async function walk(current: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(current, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) await walk(full);
      } else if (entry.isFile()) {
        const lower = entry.name.toLowerCase();
        if (lower.endsWith('.d.ts') || lower.endsWith('.map')) continue;
        if (SOURCE_EXT.has(extname(lower))) out.push(full);
      }
    }
  }
  await walk(dir);
  // Test files ship in many packages (`*.spec.js` next to the code) and carry
  // deliberate attack strings as fixtures; they are not server source.
  return out.filter((file) => !isTestPath(file, [dir], { rootIsUnit: true }));
}
