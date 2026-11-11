import { basename, dirname, extname, join, relative, resolve } from 'node:path';
import type { MCPDataFile, MCPServerEntry, MCPServerSource } from './types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { fetchNpmPackageSource, packageExtractDir, type PackageFetchResult } from './package-fetcher.js';
import { collectServerDependencies } from './server-dependencies.js';
import { parse as parseTOML } from 'smol-toml';
import { binaryFileFormat, binaryFormat, isScriptFile, sourceText } from '../analyzers/binary-text.js';
import { readCappedFile, ScanLimitError } from '../core/file-limits.js';
import { isExcludedPath } from '../core/utils.js';
import { isTestPath } from '../analyzers/test-paths.js';
import { shellLaunchTarget } from './shell-launch.js';

/**
 * A command's executable name, also when the config gives it as a path —
 * desktop configs often spell out `/Users/me/.local/bin/uvx` or an nvm `npx`.
 */
export function runnerName(command: string): string {
  return basename(command.replace(/\\/g, '/')).replace(/\.(?:cmd|exe)$/i, '');
}

/** Runners that fetch and run a published package. */
const PACKAGE_RUNNERS = new Set(['npx', 'bunx', 'uvx', 'pnpx', 'pipx']);

/** npx/bunx options that consume the next argument. */
const NPX_VALUE_FLAGS = new Set(['--registry', '--cache', '--userconfig', '--prefix', '-c', '--call', '--node-options', '--workspace', '-w']);

/**
 * The package spec a runner installs: the value of `--package`/`-p` (npx) or
 * `--from` (uvx) when given, otherwise the first argument that is not an
 * option or an option's value (`uvx --link-mode copy --from x==1 x` → `x==1`).
 */
function runnerPackageSpec(args: string[], valueFlags: Set<string>, packageFlags: Set<string>): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (packageFlags.has(arg)) return args[i + 1];
    const inline = /^(--[\w-]+)=(.+)$/.exec(arg);
    if (inline && packageFlags.has(inline[1])) return inline[2];
    if (valueFlags.has(arg)) { i++; continue; }
    if (arg.startsWith('-')) continue;
    return arg;
  }
  return undefined;
}

export function inferPackageName(server: MCPServerEntry): string | undefined {
  if (!server.command || !server.args?.length) return undefined;

  const cmd = runnerName(server.command);
  const args = server.args;

  // npx @scope/package, npx -y pkg@1.2.3, npx -p pkg command
  if (cmd === 'npx' || cmd === 'bunx' || cmd === 'pnpx') {
    return runnerPackageSpec(args, NPX_VALUE_FLAGS, new Set(['-p', '--package']));
  }

  // uvx package, uvx --from package==1.2 command
  if (cmd === 'uvx') {
    return runnerPackageSpec(args, UV_VALUE_FLAGS, new Set(['--from']));
  }

  // uv tool run / uv run <package>; `uv [--directory d] run server.py` runs a
  // local script, not a package.
  if (cmd === 'uv') {
    if (uvRunScript(args)) return undefined;
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (UV_VALUE_FLAGS.has(arg)) { i++; continue; }
      if (arg === 'run' || arg === 'tool' || arg.startsWith('-')) continue;
      return arg;
    }
  }

  // node /path/to/server.js — a local path, handled by resolveLocalPath
  return undefined;
}

/** `python`, `python3`, `python3.12`, `py` — bare or as a path (`.venv/bin/python`). */
const PYTHON_INTERPRETER = /^(?:python(?:\d+(?:\.\d+)?)?|py)(?:\.exe)?$/i;

/** Python options that consume the next argument. */
const PYTHON_VALUE_FLAGS = new Set(['-W', '-X', '-Q']);

/** uv options (global and `run`) that consume the next argument. */
const UV_VALUE_FLAGS = new Set([
  '--directory', '--project', '--python', '-p', '--with', '--with-editable',
  '--with-requirements', '--from', '--env-file', '--index', '--index-url',
  '--default-index', '--extra-index-url', '--extra', '--group', '--package',
  '--config-file', '--cache-dir', '--link-mode', '--index-strategy', '--keyring-provider',
  '--constraints', '--overrides', '--prerelease', '--resolution', '--exclude-newer',
  '--refresh-package', '--reinstall-package', '--upgrade-package',
]);

/**
 * The script a `uv … run …` invocation executes, resolved against
 * `--directory` (the MCP quickstart form is `uv --directory <dir> run server.py`).
 * Undefined when the run target is a package/console script, not a `.py` file.
 */
export function uvRunScript(args: string[]): string | undefined {
  let directory: string | undefined;
  let afterRun = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--directory' || arg === '--project') {
      directory = args[++i];
      continue;
    }
    if (arg.startsWith('--directory=')) {
      directory = arg.slice('--directory='.length);
      continue;
    }
    if (UV_VALUE_FLAGS.has(arg)) { i++; continue; }
    if (arg.startsWith('-')) continue;
    if (!afterRun) {
      if (arg !== 'run') return undefined; // `uv tool run`, `uv pip …` — not a script
      afterRun = true;
      continue;
    }
    // First `.py` positional after `run`: covers `run server.py`,
    // `run python server.py` and `run mcp run server.py`.
    if (arg.endsWith('.py')) return directory ? resolve(directory, arg) : resolve(arg);
  }
  return undefined;
}

function pythonScript(args: string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '-m' || arg === '-c') return undefined; // module / inline code, no file
    if (PYTHON_VALUE_FLAGS.has(arg)) { i++; continue; }
    if (arg.startsWith('-')) continue;
    return resolve(arg);
  }
  return undefined;
}

/** The interpreter a command names, judged by basename so `/…/.venv/bin/python` counts. */
function interpreterOf(command: string): 'node' | 'python' | 'uv' | undefined {
  const base = basename(command.replace(/\\/g, '/'));
  if (base === 'node' || base === 'node.exe') return 'node';
  if (base === 'uv' || base === 'uv.exe') return 'uv';
  if (PYTHON_INTERPRETER.test(base)) return 'python';
  return undefined;
}

/**
 * Programs a config names by path that run another program — shells,
 * wrappers, interpreters, package managers, container engines. Their own
 * binary is not the server's code.
 */
const LAUNCHERS = new Set([
  'env', 'sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'busybox', 'cmd', 'powershell', 'pwsh',
  'nohup', 'caffeinate', 'sudo', 'doas', 'time', 'nice', 'ionice', 'timeout', 'stdbuf', 'setsid', 'exec', 'xargs', 'arch',
  'docker', 'podman', 'nerdctl', 'kubectl', 'ssh', 'flatpak', 'snap',
  'node', 'nodejs', 'deno', 'bun', 'bunx', 'tsx', 'ts-node', 'npx', 'pnpx', 'npm', 'pnpm', 'yarn', 'corepack',
  'uv', 'uvx', 'pipx', 'pip', 'poetry', 'pdm', 'hatch', 'conda', 'mamba', 'fastmcp', 'mcp',
  'ruby', 'perl', 'php', 'java', 'dotnet', 'go', 'cargo', 'lua', 'osascript', 'open',
]);

export function resolveLocalPath(server: MCPServerEntry): string | undefined {
  if (!server.command) return undefined;

  const cmd = server.command;
  const args = server.args ?? [];

  // A package runner given by path runs a published package, not this file.
  if (PACKAGE_RUNNERS.has(runnerName(cmd))) return undefined;

  // Interpreter + script, also when the interpreter is given by path — an
  // absolute nvm `node` or venv `python` is the norm in desktop configs, and
  // reading the interpreter binary as "server source" analyzed nothing.
  switch (interpreterOf(cmd)) {
    case 'node':
      for (const arg of args) {
        if (arg.startsWith('-')) continue;
        return resolve(arg);
      }
      return undefined;
    case 'python':
      return pythonScript(args);
    case 'uv':
      return uvRunScript(args);
  }

  // Direct path execution — of the server itself, not a launcher that runs
  // something else (`/usr/bin/env npx …`, `/bin/bash -c`, `docker run`)
  if ((cmd.startsWith('/') || cmd.startsWith('./') || cmd.startsWith('../')) && !LAUNCHERS.has(runnerName(cmd).toLowerCase())) {
    return resolve(cmd);
  }

  return undefined;
}

/** Python when run through a Python interpreter/uv, named `.py`, or with a python shebang. */
function sourceLanguage(server: MCPServerEntry, path: string | undefined, code: string): 'javascript' | 'python' {
  const interpreter = server.command ? interpreterOf(server.command) : undefined;
  if (interpreter === 'python' || interpreter === 'uv') return 'python';
  if (path?.endsWith('.py')) return 'python';
  if (/^#!.*\bpython/.test(code)) return 'python';
  return 'javascript';
}

/**
 * A server source file's text, or undefined. `onFailure` hears why a source
 * that is there wasn't read: EACCES/EPERM, or over the content-scan size
 * limit (MAX_SCAN_FILE_BYTES, as for skill and IOC files — a 10 MB bundle
 * parsed whole ran V8 out of heap). `onBinary` hears the format of a compiled
 * binary (a Go/Rust server), which is not source. A snapshot that omits a
 * binary asset without its head stays silent.
 */
async function readSourceFile(
  filePath: string,
  fs: FSProvider,
  onFailure?: (message: string) => void,
  onBinary?: (format: string) => void,
  /** The OS runs the file itself (the config's command): its magic bytes decide, not its extension. */
  executed = false,
): Promise<string | undefined> {
  try {
    // Judged on its head before its size: a Go/Rust server binary is often
    // over the content-scan limit, and is no unreadable source either way
    const early = await headBinaryFormat(fs, filePath, executed);
    if (early) {
      onBinary?.(early);
      return undefined;
    }
    const content = await readCappedFile(fs, filePath);
    // A native executable (a Mach-O / ELF server binary launched by path) is
    // not source: read as text, its bytes match "invisible character" and
    // "encoded string" patterns everywhere. A script never is (binary-text.ts).
    const format = await binaryFileFormat(fs, filePath, content);
    if (format) {
      onBinary?.(format);
      return undefined;
    }
    return sourceText(content);
  } catch (err) {
    if (err instanceof ScanLimitError) {
      if (err.reason !== 'omitted') onFailure?.(`${filePath}: ${err.detail}`);
    } else if (isDenied(err)) {
      onFailure?.(err instanceof Error ? err.message : String(err));
    }
    return undefined;
  }
}

/**
 * The binary format of a file's raw head, when it is no script (extension or
 * `#!`). A file the OS executes directly is a script only by its `#!`: the
 * kernel never looks at the extension, so a Mach-O named `server.js` runs as
 * a Mach-O.
 */
async function headBinaryFormat(fs: FSProvider, filePath: string, executed = false): Promise<string | undefined> {
  if (!executed && isScriptFile(filePath, '')) return undefined;
  const head = await fs.readHead?.(filePath, 4096).catch(() => undefined);
  if (!head || (head[0] === 0x23 && head[1] === 0x21)) return undefined;
  return binaryFormat(head);
}

async function isFile(path: string, fs: FSProvider): Promise<boolean> {
  return fs.stat(path).then((st) => st.isFile(), () => false);
}

function isDenied(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException | null)?.code;
  return code === 'EACCES' || code === 'EPERM';
}

/**
 * The TypeScript source a build output was compiled from, by the usual
 * layout: `dist/index.js` → `src/index.ts`, `build/server.mjs` → `src/server.mts`.
 */
function sourceTwins(dir: string, built: string): string[] {
  const rel = relative(dir, built).split(/[\\/]/);
  if (rel.length < 2 || !BUILD_DIRS.has(rel[0])) return [];
  const stem = join(dir, 'src', ...rel.slice(1)).replace(/\.([mc]?)js$/i, '');
  const ext = /\.([mc]?)js$/i.exec(built)?.[1] ?? '';
  return [`${stem}.${ext}ts`, `${stem}.tsx`];
}

/** Directories a build writes its output to. */
const BUILD_DIRS = new Set(['dist', 'build', 'lib', 'out']);

/**
 * The entries package.json declares — `main` and every `bin` — each only when
 * its file is there: an unbuilt checkout names `dist/index.js` before `tsc`
 * has made it, and its code is the TypeScript source the build would compile.
 * `main` is what `require` loads, `bin` what `npx` runs: they may differ.
 */
async function declaredEntries(dir: string, fs: FSProvider): Promise<string[]> {
  const pkgPath = join(dir, 'package.json');
  if (!(await fs.access(pkgPath))) return [];
  let pkg: { main?: unknown; bin?: unknown };
  try {
    pkg = JSON.parse(await fs.readFile(pkgPath));
  } catch {
    return [];
  }
  const bins = typeof pkg.bin === 'string' ? [pkg.bin] : pkg.bin && typeof pkg.bin === 'object' ? Object.values(pkg.bin) : [];
  const declared = [pkg.main, ...bins].filter((e): e is string => typeof e === 'string' && e !== '').map((e) => join(dir, e));
  const out: string[] = [];
  for (const entry of declared) {
    // as Node resolves `main`: the file, with `.js`, or a directory's index.js; else its TypeScript source
    let found: string | undefined;
    for (const file of [entry, `${entry}.js`, join(entry, 'index.js')]) if (!found && (await isFile(file, fs))) found = file;
    for (const twin of sourceTwins(dir, entry)) if (!found && (await isFile(twin, fs))) found = twin;
    if (found && !out.includes(found)) out.push(found);
  }
  return out;
}

async function findMainEntry(dir: string, fs: FSProvider): Promise<string | undefined> {
  const [declared] = await declaredEntries(dir, fs);
  if (declared) return declared;

  // Common entry points (a Python package dir runs its __main__.py)
  const candidates = [
    'index.js', 'index.ts', 'src/index.js', 'src/index.ts', 'main.js', 'server.js',
    '__main__.py', 'server.py', 'main.py',
  ];
  for (const candidate of candidates) {
    const fullPath = join(dir, candidate);
    if (await fs.access(fullPath)) return fullPath;
  }

  return undefined;
}

export interface ResolveSourcesOptions {
  fs?: FSProvider;
  /**
   * When true, npm-packaged servers (npx) whose source isn't on local disk are
   * downloaded from the registry (download-only, never executed) so the
   * AST/tool checks can analyze them. Opt-in: off by default to preserve
   * offline-first behavior. uvx/PyPI packages are not fetched (only the npm
   * download path exists); local Python scripts are read from disk and get the
   * Python sink analyzer.
   */
  resolvePackages?: boolean;
  cacheDir?: string;
  /** Injectable npm-spec → source resolver, for hermetic unit tests. */
  npmFetcher?: (spec: string) => Promise<string | undefined | PackageFetchResult>;
}

function isNpmCommand(cmd?: string): boolean {
  const runner = cmd ? runnerName(cmd) : '';
  return runner === 'npx' || runner === 'bunx' || runner === 'pnpx';
}

export async function resolveServerSources(
  servers: MCPServerEntry[],
  options: ResolveSourcesOptions = {},
): Promise<MCPServerSource[]> {
  const provider = options.fs ?? new LocalFSProvider();
  const sources: MCPServerSource[] = [];

  for (const server of servers) {
    const packageName = inferPackageName(server);
    const localPath = resolveLocalPath(server);

    let sourceCode: string | undefined;
    let entryFile: string | undefined;
    // The server's code is there but this scan can't read it (EACCES, or over
    // the size limit): every source check would pass it unseen, so it is
    // reported (SOURCE-READ)
    let readFailure: string | undefined;
    const denied = (message: string) => { readFailure ??= message; };
    // A compiled server (Go/Rust): its format; nothing to analyze
    let compiledBinary: string | undefined;
    const binary = (format: string) => { compiledBinary ??= format; };

    // Files of the server not analyzed (permissions, limits, a launched
    // script that isn't there): the source was read only in part
    const hidden: SkippedFile[] = [];
    let launchedEntry: string | undefined;
    if (localPath) {
      // Run by the OS itself (no interpreter in the config): its magic bytes decide what it is
      const executed = !interpreterOf(server.command ?? '');
      sourceCode = await readSourceFile(localPath, provider, denied, binary, executed);
      if (sourceCode) entryFile = localPath;
      // A shell launcher (`exec node "$(dirname "$0")/real.js"`): the server's code is the file it starts
      const launched = sourceCode ? shellLaunchTarget(localPath, sourceCode) : undefined;
      if (launched) {
        const code = await readSourceFile(launched, provider, undefined, binary);
        if (code) {
          sourceCode = code;
          entryFile = launchedEntry = launched;
        } else if (!compiledBinary) {
          hidden.push({ path: launched, reason: `${launched}: started by ${basename(localPath)}, but could not be read — only the launcher was analyzed` });
        }
      }

      // If it's a directory, find the main entry
      if (!sourceCode && !compiledBinary) {
        const entry = await findMainEntry(localPath, provider);
        if (entry) {
          sourceCode = await readSourceFile(entry, provider, denied, binary);
          if (sourceCode) entryFile = entry;
        } else {
          // A server directory that can't be listed hides its entry file
          await provider.readdir(localPath).catch((err: unknown) => {
            if (isDenied(err)) denied(err instanceof Error ? err.message : String(err));
          });
        }
      }
    }

    // Opt-in: resolve npm-packaged servers so their source feeds the AST/tool
    // checks. Download-only, never executed (see package-fetcher).
    let packageDir: string | undefined;
    let resolveFailure: MCPServerSource['resolveFailure'];
    if (!sourceCode && packageName && options.resolvePackages && isNpmCommand(server.command)) {
      const fetcher =
        options.npmFetcher ??
        ((spec: string) => fetchNpmPackageSource(spec, { cacheDir: options.cacheDir }));
      const fetched = await fetcher(packageName);
      const result: PackageFetchResult = typeof fetched === 'object' ? fetched : { source: fetched };
      sourceCode = result.source;
      if (sourceCode) packageDir = packageExtractDir(packageName, options.cacheDir);
      else resolveFailure = result.failure ?? { reason: 'npm-failed' };
    }

    const language = sourceCode ? sourceLanguage(server, entryFile ?? localPath, sourceCode) : undefined;
    // The modules the entry imports (a thin index.js whose tools live in
    // ./tools/*.js), or the rest of its Python package
    let sourceRoot: string | undefined;
    let partialFailure: string | undefined;
    if (sourceCode && entryFile) {
      const files = language === 'python' ? await withPythonPackage(entryFile, provider, hidden) : await withLocalImports(entryFile, sourceCode, provider, undefined, hidden);
      if (files.length > 1) {
        const root = language === 'python' ? dirname(entryFile) : await serverRoot(entryFile, provider);
        const read = await readServerFiles(files, root, provider, new Map([[entryFile, sourceCode]]));
        sourceCode = read.code;
        if (read.marked) sourceRoot = root;
        hidden.push(...read.skipped);
      }
    }
    if (hidden.length > 0) partialFailure = describeSkipped(hidden);

    const source: MCPServerSource = {
      serverName: server.name,
      packageName,
      // a launcher's server code is the file it starts: findings point there
      localPath: launchedEntry ?? localPath,
      sourceCode,
      ...(resolveFailure ? { resolveFailure } : {}),
      ...(readFailure && !sourceCode ? { readFailure } : {}),
      ...(partialFailure ? { readFailure: partialFailure } : {}),
      ...(compiledBinary && !sourceCode ? { compiledBinary } : {}),
      ...(sourceRoot ? { sourceRoot } : {}),
    };
    if (language === 'python') {
      source.language = 'python';
    }
    if (sourceCode && entryFile) {
      const dataFiles = await referencedDataFiles(entryFile, sourceCode, provider);
      if (dataFiles.length > 0) source.dataFiles = dataFiles;
    }
    const dependencies = entryFile
      ? await collectServerDependencies(entryFile, source.language ?? 'javascript', provider)
      : packageDir
        ? await collectServerDependencies(join(packageDir, 'package.json'), 'javascript', provider, { searchParents: false })
        : [];
    if (dependencies.length > 0) source.dependencies = dependencies;
    sources.push(source);
  }

  return sources;
}

const DATA_EXTENSIONS = new Set(['.txt', '.md', '.json', '.html', '.htm', '.csv', '.yaml', '.yml', '.xml']);
const SOURCE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.py']);
/** Names that exist next to server code but are tooling, not runtime data. */
const NOT_DATA = new Set(['node_modules', 'package.json', 'package-lock.json', 'tsconfig.json', 'pyproject.toml', 'README.md', 'CHANGELOG.md', 'LICENSE.md']);
const MAX_PATH_CANDIDATES = 200;
const MAX_DATA_FILES = 50;
const MAX_DATA_FILE_BYTES = 256 * 1024;
/** A relative file or folder name in a string literal: `'documents'`, `"prompts/system.md"`. */
const PATH_LITERAL = /["'`]([A-Za-z0-9_][\w.-]*(?:\/[\w.-]+)*)["'`]/g;

/**
 * Text files a local server reads at runtime: a file or folder named in a
 * string literal of its source that exists next to its entry file
 * (`join(__dirname, 'documents', id)` → `documents/*`). Files merely shipped
 * alongside (README, LICENSE) are not included — a README quoting an attack
 * is not the attack.
 */
async function referencedDataFiles(entryFile: string, code: string, fs: FSProvider): Promise<MCPDataFile[]> {
  const base = dirname(entryFile);
  const names = new Set<string>();
  for (const m of code.matchAll(PATH_LITERAL)) {
    const name = m[1];
    // A data-file name, or a bare folder name; not dotted identifiers or versions.
    const ext = extname(name).toLowerCase();
    if (ext ? !DATA_EXTENSIONS.has(ext) : name.length > 40) continue;
    if (NOT_DATA.has(name.split('/')[0])) continue;
    names.add(name);
    if (names.size >= MAX_PATH_CANDIDATES) break;
  }

  const files: string[] = [];
  for (const name of names) {
    const path = join(base, name);
    if (path === entryFile || files.length >= MAX_DATA_FILES) continue;
    try {
      const st = await fs.stat(path);
      if (st.isFile() && DATA_EXTENSIONS.has(extname(path).toLowerCase())) {
        files.push(path);
      } else if (st.isDirectory() && !name.startsWith('.')) {
        for (const entry of await fs.readdir(path)) {
          if (DATA_EXTENSIONS.has(extname(entry).toLowerCase())) files.push(join(path, entry));
        }
      }
    } catch {
      // not there — just a string
    }
  }

  const out: MCPDataFile[] = [];
  for (const path of files.slice(0, MAX_DATA_FILES)) {
    const content = await readSourceFile(path, fs);
    if (content !== undefined && content.length <= MAX_DATA_FILE_BYTES) out.push({ path, content });
  }
  return out;
}

/** Server code a source tree names explicitly: imports the MCP SDK or FastMCP. */
const MCP_SDK_REFERENCE = /@modelcontextprotocol\/sdk|\bfrom\s+mcp\b|\bimport\s+mcp\b|\bFastMCP\b/;

/** Directories in a server checkout that hold no server code. */
const JS_SKIP_DIRS = new Set(['example', 'examples', 'coverage', 'scripts', 'docs']);
/** Tooling config beside the code (`vitest.config.ts`, `eslint.config.mjs`). */
const TOOL_CONFIG_FILE = /\.config\.[cm]?[jt]s$|^\.?eslintrc\.c?js$|^jest\.setup\.[jt]s$/;

/**
 * The source files of a server checkout, subdirectories too: vendor, VCS,
 * test, example and tooling files skipped, at most MAX_LOCAL_MODULES.
 */
async function sourceFilesUnder(dir: string, fs: FSProvider, denied?: SkippedFile[]): Promise<string[]> {
  const candidates: string[] = [];
  const pending = [dir];
  // one past the limit, to know the checkout is larger
  for (let d = pending.shift(); d !== undefined && candidates.length <= MAX_LOCAL_MODULES; d = pending.shift()) {
    let entries;
    try {
      entries = await fs.readdirEntries(d);
    } catch (err) {
      // A directory of the checkout that can't be listed hides its files
      if (isDenied(err)) denied?.push({ path: d, reason: err instanceof Error ? err.message : String(err) });
      continue;
    }
    for (const e of [...entries].sort((a, b) => a.name.localeCompare(b.name))) {
      const path = join(d, e.name);
      if (e.isDirectory) {
        if (!e.name.startsWith('.') && !JS_SKIP_DIRS.has(e.name) && !isExcludedPath(dir, path, { keepBuildOutput: true })) pending.push(path);
      } else if (
        e.isFile &&
        SOURCE_EXTENSIONS.has(extname(e.name).toLowerCase()) &&
        !e.name.endsWith('.d.ts') &&
        !TOOL_CONFIG_FILE.test(e.name) &&
        !isTestPath(path, [dir], { rootIsUnit: true })
      ) {
        candidates.push(path);
      }
    }
  }
  return capFiles(candidates, MAX_LOCAL_MODULES, denied);
}

/**
 * The server code in a directory without a declared entry: its source files
 * (sourceFilesUnder()) that use the MCP SDK and the modules they import
 * first, then the directory's other source files — tools loaded by a
 * computed path (`import(new URL("./tools/" + f, import.meta.url))`) import
 * nothing the graph can see. Files of the other language than the server's
 * stay out, and so does a second build of a module already in (src/ + dist/).
 */
async function serverFilesIn(dir: string, fs: FSProvider, skipped?: SkippedFile[]): Promise<string[]> {
  const candidates = await sourceFilesUnder(dir, fs, skipped);
  const usingSdk: string[] = [];
  for (const file of candidates) {
    const code = await readSourceFile(file, fs);
    if (code && MCP_SDK_REFERENCE.test(code)) usingSdk.push(file);
  }
  if (usingSdk.length === 0) return candidates;
  const graph = new Set<string>();
  for (const file of usingSdk) {
    const code = (await readSourceFile(file, fs)) ?? '';
    const imported = file.endsWith('.py') ? await withPythonPackage(file, fs, skipped) : await withLocalImports(file, code, fs, dir, skipped);
    for (const f of imported) graph.add(f);
  }
  const python = [...graph].every((f) => f.endsWith('.py'));
  const rest = withoutTwins(dir, [...graph], candidates.filter((f) => f.endsWith('.py') === python));
  return capFiles([...graph, ...rest], MAX_LOCAL_MODULES, skipped);
}

/** Modules followed from one server's entry. */
const MAX_LOCAL_MODULES = 200;
/**
 * Source read for one server, all files together: a 4.5 MiB minified file
 * takes ~45 s to analyze, and four of them took three minutes. The entry is
 * always read (it has the 5 MiB per-file limit); a module past the total is
 * skipped and reported.
 */
export const MAX_SERVER_SOURCE_BYTES = 6 * 1024 * 1024;

/** Extensions a relative import may leave out, in Node / TypeScript resolution order. */
const JS_EXTENSIONS = ['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx'];
/**
 * `from './x'`, `import './x'`, `import('./x')`, `require('./x')`,
 * `export … from './x'`: relative specifiers only — packages are not the
 * server's own code. The specifier class excludes quotes and newlines, so the
 * scan is linear on minified bundles.
 */
const RELATIVE_IMPORT = /(?:\bfrom|\bimport|\brequire)\s*(?:\(\s*)?(["'`])(\.{1,2}\/[^"'`\r\n]{0,512})\1/g;

/**
 * The directory a local server's modules are confined to: the nearest
 * ancestor of its entry with a package.json (a `dist/index.js` imports
 * `../lib/x.js`), at most four levels up, else the entry's directory.
 */
async function serverRoot(entry: string, fs: FSProvider): Promise<string> {
  let dir = dirname(entry);
  for (let i = 0; i < 4; i++) {
    if (await fs.access(join(dir, 'package.json'))) return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return dirname(entry);
}

/**
 * The file a relative specifier names: as written, with an extension, or a
 * directory's index; `./x.js` may be `./x.ts` in TypeScript source. A module
 * hidden by permissions (an untraversable directory) is `denied`.
 */
async function resolveImport(from: string, specifier: string, fs: FSProvider): Promise<{ path?: string; denied?: string }> {
  const base = resolve(dirname(from), specifier.replace(/[?#].*$/, ''));
  const ext = extname(base).toLowerCase();
  const candidates = JS_EXTENSIONS.includes(ext)
    ? [base, base.replace(/\.([mc]?)js$/i, '.$1ts'), base.replace(/\.js$/i, '.tsx')]
    : [...JS_EXTENSIONS.map((e) => base + e), ...JS_EXTENSIONS.map((e) => join(base, `index${e}`))];
  let denied: string | undefined;
  for (const path of new Set(candidates)) {
    try {
      if ((await fs.stat(path)).isFile()) return { path };
    } catch (err) {
      // not this one — unless permissions hide it
      if (isDenied(err)) denied ??= err instanceof Error ? err.message : String(err);
    }
  }
  return denied ? { denied } : {};
}

/**
 * A JavaScript/TypeScript entry plus the local modules it imports,
 * transitively: a server whose entry only wires up `./tools/run.js` keeps its
 * sinks there. Confined to the server's directory (`root`, else serverRoot()),
 * vendor dirs skipped, at most MAX_LOCAL_MODULES files.
 */
async function withLocalImports(entry: string, entryCode: string, fs: FSProvider, root?: string, denied?: SkippedFile[]): Promise<string[]> {
  if (!JS_EXTENSIONS.includes(extname(entry).toLowerCase()) && !/^#!.*\bnode\b/.test(entryCode)) return [entry];
  const base = root ?? (await serverRoot(entry, fs));
  const files = [entry];
  const seen = new Set(files);
  // Specifiers already resolved (or not) from a directory: each costs a stat per candidate
  const tried = new Set<string>();
  for (let i = 0; i < files.length; i++) {
    const code = i === 0 ? entryCode : await readSourceFile(files[i], fs);
    if (!code) continue;
    for (const m of code.matchAll(RELATIVE_IMPORT)) {
      const key = `${dirname(files[i])}\0${m[2]}`;
      if (tried.has(key)) continue;
      tried.add(key);
      const found = await resolveImport(files[i], m[2], fs);
      if (found.denied) denied?.push({ path: resolve(dirname(files[i]), m[2]), reason: found.denied });
      const path = found.path;
      if (!path || seen.has(path)) continue;
      seen.add(path);
      const rel = relative(base, path);
      if (rel.startsWith('..') || isExcludedPath(base, dirname(path), { keepBuildOutput: true })) continue;
      if (files.length >= MAX_LOCAL_MODULES) {
        // one module more than the limit: the rest of the graph goes unread, and is reported
        denied?.push(moduleLimit(path, MAX_LOCAL_MODULES));
        return files;
      }
      files.push(path);
    }
  }
  return files;
}

/** A file of a server not analyzed, and why. */
interface SkippedFile {
  path: string;
  reason: string;
}

/** The first file past a module limit, reported: the rest of the server's code was not analyzed. */
function moduleLimit(first: string, limit: number): SkippedFile {
  return { path: first, reason: `${first}: not analyzed — the server has more than ${limit} source modules, only the first ${limit} were read` };
}

/** At most `limit` files; the cut is reported in `skipped` (never dropped silently). */
function capFiles(files: string[], limit: number, skipped?: SkippedFile[]): string[] {
  if (files.length <= limit) return files;
  skipped?.push(moduleLimit(files[limit], limit));
  return files.slice(0, limit);
}

/**
 * Where a file sits in a checkout once its build directory and extension are
 * set aside: `src/tools/run.ts` and `dist/tools/run.js` are one module,
 * compiled. Used to keep a checkout's sweep from reading both.
 */
function moduleKey(root: string, file: string): string {
  const parts = relative(root, file).split(/[\\/]/);
  if (parts.length > 1 && (parts[0] === 'src' || BUILD_DIRS.has(parts[0]))) parts.shift();
  return parts.join('/').replace(/\.(?:[mc]?[jt]s|[jt]sx)$/i, '');
}

/** Files of `rest` that are neither in `taken` nor another build of one of them (moduleKey()). */
function withoutTwins(root: string, taken: string[], rest: string[]): string[] {
  const keys = new Set(taken.map((f) => moduleKey(root, f)));
  const out: string[] = [];
  // the source before its build output: findings point at the code as written
  const built = (f: string) => Number(BUILD_DIRS.has(relative(root, f).split(/[\\/]/)[0]));
  for (const f of [...rest].sort((a, b) => built(a) - built(b))) {
    const key = moduleKey(root, f);
    if (taken.includes(f) || keys.has(key)) continue;
    keys.add(key);
    out.push(f);
  }
  return out;
}

/**
 * The files of one server joined for analysis (`// === <file> ===` headers,
 * relative to `root`), within MAX_SERVER_SOURCE_BYTES; files not read
 * (permissions, size limits) are returned as skipped. `known` holds texts
 * already read.
 */
async function readServerFiles(
  files: string[],
  root: string,
  fs: FSProvider,
  known = new Map<string, string>(),
): Promise<{ code: string; parts: number; marked: boolean; skipped: SkippedFile[] }> {
  const parts: string[] = [];
  const skipped: SkippedFile[] = [];
  let total = 0;
  for (const file of files) {
    let failure: string | undefined;
    const code = known.get(file) ?? (await readSourceFile(file, fs, (message) => { failure = message; }));
    if (code === undefined) {
      if (failure) skipped.push({ path: file, reason: failure });
      continue;
    }
    if (parts.length > 0 && total + code.length > MAX_SERVER_SOURCE_BYTES) {
      skipped.push({ path: file, reason: `${file}: not analyzed — the server's source is over the ${MAX_SERVER_SOURCE_BYTES / (1024 * 1024)} MiB total analysis limit` });
      continue;
    }
    total += code.length;
    parts.push(files.length > 1 ? `// === ${relative(root, file) || basename(file)} ===\n${code}` : code);
  }
  return { code: parts.join('\n\n'), parts: parts.length, marked: files.length > 1, skipped };
}

/** One SOURCE-READ line for a server's skipped modules: the first reason, and how many more. */
function describeSkipped(skipped: SkippedFile[]): string {
  const more = skipped.length > 1 ? ` (and ${skipped.length - 1} more module(s) not analyzed)` : '';
  return `${skipped[0].reason}${more}`;
}

/** Directories inside a Python package that are not server code. */
const PY_SKIP_DIRS = new Set(['tests', 'test', '__pycache__', '.venv', 'venv', 'node_modules', '.git', 'build', 'dist', 'site-packages']);
const MAX_PY_PACKAGE_FILES = 200;

/** Every module of a Python package directory, entry-relevant first, tests and caches skipped. */
async function pythonModules(pkgDir: string, fs: FSProvider, skipped?: SkippedFile[]): Promise<string[]> {
  const files: string[] = [];
  const pending = [pkgDir];
  // one past the limit, to know the package is larger
  for (let dir = pending.shift(); dir !== undefined && files.length <= MAX_PY_PACKAGE_FILES; dir = pending.shift()) {
    let entries;
    try {
      entries = await fs.readdirEntries(dir);
    } catch {
      continue;
    }
    for (const e of [...entries].sort((a, b) => a.name.localeCompare(b.name))) {
      if (e.isDirectory && !PY_SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) pending.push(join(dir, e.name));
      else if (e.isFile && e.name.endsWith('.py') && !/^test_|_test\.py$|^conftest\.py$/.test(e.name)) files.push(join(dir, e.name));
    }
  }
  // __main__ / server first: the entry the console script or `python -m` runs
  const rank = (f: string) => (/(?:^|\/)(?:__main__|server)\.py$/.test(f) ? 0 : 1);
  return capFiles(files.sort((a, b) => rank(a) - rank(b)), MAX_PY_PACKAGE_FILES, skipped);
}

/**
 * A Python server checkout (`pyproject.toml` + `src/<pkg>/` or `<pkg>/`): the
 * package its console script runs (`[project.scripts] x = "pkg.server:main"`),
 * else the package that imports the MCP SDK. Undefined when the directory is
 * not laid out as a Python package.
 */
async function pythonPackageFiles(dir: string, fs: FSProvider): Promise<string[] | undefined> {
  const roots = [join(dir, 'src'), dir];
  // Top-level modules of the console scripts: `x = "pkg.server:main"` → pkg
  const scriptPackages = new Set<string>();
  try {
    const project = (parseTOML(await fs.readFile(join(dir, 'pyproject.toml'))) as Record<string, unknown>).project as Record<string, unknown> | undefined;
    const scripts = project?.scripts && typeof project.scripts === 'object' ? Object.values(project.scripts as Record<string, unknown>) : [];
    for (const target of scripts) {
      const mod = typeof target === 'string' ? target.split(':')[0].trim().split('.')[0] : '';
      if (mod) scriptPackages.add(mod);
    }
  } catch {
    // no pyproject, or not TOML
  }
  const candidates = new Set(scriptPackages);
  for (const root of roots) {
    let entries;
    try {
      entries = await fs.readdirEntries(root);
    } catch {
      continue;
    }
    for (const e of entries) if (e.isDirectory && !PY_SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) candidates.add(e.name);
  }
  for (const name of candidates) {
    for (const root of roots) {
      const pkg = join(root, name);
      // No __init__.py is fine: a PEP 420 namespace package (awslabs/*) still
      // imports. The SDK check below keeps unrelated directories out.
      const modules = await pythonModules(pkg, fs);
      if (modules.length === 0) continue;
      // The console script's package is the server; any other must use the SDK
      if (scriptPackages.has(name)) return modules;
      for (const f of modules) {
        const code = await readSourceFile(f, fs);
        if (code && MCP_SDK_REFERENCE.test(code)) return modules;
      }
    }
  }
  return undefined;
}

/**
 * A Python entry plus the code it imports from beside it. One in a package
 * (`server.py` beside an `__init__.py`, or importing relatively: `from .tools
 * import run`) brings the package's other modules, which hold the tools. A
 * script in a plain folder imports its siblings by name (`from tools import
 * run_cmd` — Python puts the script's directory on sys.path): those modules,
 * transitively. Reading the entry alone missed every sink they contain.
 */
async function withPythonPackage(entry: string, fs: FSProvider, skipped?: SkippedFile[]): Promise<string[]> {
  if (!entry.endsWith('.py')) return [entry];
  const dir = dirname(entry);
  const code = (await readSourceFile(entry, fs)) ?? '';
  // Leading space within the line: `^\s*` crossed every blank line after
  // each line start (100 KB of newlines: 6 s)
  const isPackage = (await fs.access(join(dir, '__init__.py'))) || /^[^\S\n\r\u2028\u2029]*from\s+\.+\w*(?:\.\w+)*\s+import\b/m.test(code);
  if (isPackage) {
    const modules = await pythonModules(dir, fs, skipped);
    return [entry, ...modules.filter((m) => m !== entry)];
  }
  return pythonSiblingImports(entry, code, fs, skipped);
}

/** `import a, b.c as d` / `from a.b import c`: the top-level module names a line imports. */
const PY_IMPORT = /^[^\S\n]*(?:from[^\S\n]+([A-Za-z_]\w*)(?:\.[\w.]*)?[^\S\n]+import\b|import[^\S\n]+([A-Za-z_][\w.]*(?:[^\S\n]+as[^\S\n]+\w+)?(?:[^\S\n]*,[^\S\n]*[A-Za-z_][\w.]*(?:[^\S\n]+as[^\S\n]+\w+)?)*))/gm;

function pythonImportedNames(code: string): string[] {
  const names = new Set<string>();
  for (const m of code.matchAll(PY_IMPORT)) {
    if (m[1]) names.add(m[1]);
    else for (const part of m[2].split(',')) names.add(part.trim().split(/\s+/)[0].split('.')[0]);
  }
  return [...names];
}

/** A flat script's sibling modules (`tools.py`, a `tools/` package), followed transitively. */
async function pythonSiblingImports(entry: string, code: string, fs: FSProvider, skipped?: SkippedFile[]): Promise<string[]> {
  const dir = dirname(entry);
  const files = [entry];
  const seen = new Set(files);
  const tried = new Set<string>();
  for (let i = 0; i < files.length; i++) {
    const text = i === 0 ? code : await readSourceFile(files[i], fs);
    // only sibling scripts import siblings by bare name; a package's modules are all in already
    if (!text || dirname(files[i]) !== dir) continue;
    for (const name of pythonImportedNames(text)) {
      if (tried.has(name)) continue;
      tried.add(name);
      const found = (await isFile(join(dir, `${name}.py`), fs))
        ? [join(dir, `${name}.py`)]
        : await fs.stat(join(dir, name)).then((st) => (st.isDirectory() && !PY_SKIP_DIRS.has(name) ? pythonModules(join(dir, name), fs, skipped) : []), () => []);
      for (const f of found) {
        if (seen.has(f)) continue;
        if (files.length >= MAX_PY_PACKAGE_FILES) {
          skipped?.push(moduleLimit(f, MAX_PY_PACKAGE_FILES));
          return files;
        }
        seen.add(f);
        files.push(f);
      }
    }
  }
  return files;
}

async function packageJsonName(dir: string, fs: FSProvider): Promise<string | undefined> {
  try {
    const name = JSON.parse(await fs.readFile(join(dir, 'package.json'))).name;
    return typeof name === 'string' && name ? name : undefined;
  } catch {
    return undefined;
  }
}

export interface SourcePathResolution {
  sources: MCPServerSource[];
  /**
   * Paths that don't exist or hold no readable server source, and files of a
   * given checkout that couldn't be read (permissions, size limit).
   */
  unreadable: string[];
}

/**
 * MCP server source given directly (`vaso mcp scan --source <path>`): an entry
 * file, or a server checkout whose entry is found as for a local server
 * (package.json main/bin, index.js, server.py, …) or, failing that, its
 * top-level files that use the MCP SDK. For server authors, and for remote
 * servers whose code you have but whose process you only connect to.
 */
export async function resolveSourcePaths(paths: string[], options: { fs?: FSProvider } = {}): Promise<SourcePathResolution> {
  const fs = options.fs ?? new LocalFSProvider();
  const sources: MCPServerSource[] = [];
  const unreadable: string[] = [];

  for (const given of paths) {
    const path = resolve(given);
    let files: string[] = [];
    // Modules and directories of the checkout permissions hide
    const hidden: SkippedFile[] = [];
    // A compiled server given directly: an inventory note, not unreadable source
    let compiledBinary: string | undefined;
    try {
      const st = await fs.stat(path);
      if (st.isFile()) {
        const code = await readSourceFile(path, fs, undefined, (format) => { compiledBinary = format; });
        files = code === undefined ? [path] : path.endsWith('.py') ? await withPythonPackage(path, fs, hidden) : await withLocalImports(path, code, fs, undefined, hidden);
      } else if (st.isDirectory()) {
        const entry = await findMainEntry(path, fs);
        const entryCode = entry ? await readSourceFile(entry, fs, undefined, (format) => { compiledBinary = format; }) : undefined;
        if (!entry) files = await serverFilesIn(path, fs, hidden);
        else if (entry.endsWith('.py') || entryCode === undefined) files = await withPythonPackage(entry, fs, hidden);
        else {
          // The modules the entry imports first, then the checkout's other
          // source files: tools loaded by a computed path (`require(join(dir,
          // name))`) import nothing the graph can see
          const graph = await withLocalImports(entry, entryCode, fs, path, hidden);
          // A `bin` other than `main` (what npx runs) is an entry too
          for (const other of (await declaredEntries(path, fs)).filter((e) => e !== entry && !graph.includes(e))) {
            const code = await readSourceFile(other, fs);
            if (code === undefined || other.endsWith('.py')) continue;
            for (const f of await withLocalImports(other, code, fs, path, hidden)) if (!graph.includes(f)) graph.push(f);
          }
          // Within the entry's top directory (`src/`): `dist/` beside it is
          // the same code compiled, and would report every finding twice
          const top = relative(path, entry).split(/[\\/]/);
          const within = top.length > 1 ? join(path, top[0]) : path;
          // …and, with the entry at the root, a module of src/ already read from dist/
          const rest = withoutTwins(path, graph, (await sourceFilesUnder(within, fs, hidden)).filter((f) => !f.endsWith('.py')));
          files = capFiles([...graph, ...rest], MAX_LOCAL_MODULES, hidden);
        }
        // A Python package checkout (pyproject + src/<pkg>/): all its modules
        if (!entry && (files.length === 0 || files.every((f) => f.endsWith('.py')) || (await fs.access(join(path, 'pyproject.toml'))))) {
          const pkgFiles = await pythonPackageFiles(path, fs);
          if (pkgFiles) files = pkgFiles;
        }
      }
    } catch {
      // reported below
    }

    if (compiledBinary && files.length <= 1) {
      sources.push({ serverName: basename(path), localPath: files[0] ?? path, compiledBinary });
      continue;
    }

    const root = (await fs.stat(path).then((st) => st.isDirectory()).catch(() => false)) ? path : dirname(path);
    const read = await readServerFiles(files, root, fs);
    // Files of the checkout not read (permissions, size limits): reported as
    // SOURCE-READ in the report, like a configured server's
    const skipped = [...read.skipped, ...hidden];
    if (read.parts === 0) {
      unreadable.push(given);
      if (skipped.length > 0) sources.push({ serverName: basename(path), localPath: files[0] ?? path, readFailure: describeSkipped(skipped) });
      continue;
    }
    unreadable.push(...skipped.map((f) => f.path));

    const sourceCode = read.code;
    const entryFile = files[0];
    const source: MCPServerSource = { serverName: basename(path), localPath: entryFile, sourceCode };
    if (skipped.length > 0) source.readFailure = describeSkipped(skipped);
    if (read.marked) source.sourceRoot = root;
    // The name it is published under, for the provenance (typosquat) check.
    const packageName = await packageJsonName(dirname(entryFile), fs);
    if (packageName) source.packageName = packageName;
    const python = files.every((f) => f.endsWith('.py')) || /^#!.*\bpython/.test(sourceCode);
    if (python) source.language = 'python';
    const dataFiles = await referencedDataFiles(entryFile, sourceCode, fs);
    if (dataFiles.length > 0) source.dataFiles = dataFiles;
    const dependencies = await collectServerDependencies(entryFile, source.language ?? 'javascript', fs);
    if (dependencies.length > 0) source.dependencies = dependencies;
    sources.push(source);
  }

  return { sources, unreadable };
}
