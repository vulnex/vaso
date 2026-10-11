import { basename, join, resolve } from 'node:path';
import type { MCPServerEntry, MCPServerSource } from './types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { resolveNpmPackageSource } from './package-fetcher.js';

export function inferPackageName(server: MCPServerEntry): string | undefined {
  if (!server.command || !server.args?.length) return undefined;

  const cmd = server.command;
  const args = server.args;

  // npx @scope/package or npx package
  if (cmd === 'npx' || cmd === 'npx.cmd') {
    // Skip flags like -y, --yes, -p, --package
    for (const arg of args) {
      if (arg.startsWith('-')) continue;
      return arg;
    }
  }

  // uvx package
  if (cmd === 'uvx' || cmd === 'uv') {
    // `uv [--directory d] run server.py` runs a local script, not a package.
    if (cmd === 'uv' && uvRunScript(args)) return undefined;
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (UV_VALUE_FLAGS.has(arg)) { i++; continue; }
      if (arg === 'run' || arg === 'tool' || arg.startsWith('-')) continue;
      return arg;
    }
  }

  // node /path/to/server.js -> try to find package.json
  if (cmd === 'node' || cmd === 'node.exe') {
    for (const arg of args) {
      if (arg.startsWith('-')) continue;
      return undefined; // local path, handled by resolveLocalPath
    }
  }

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
  '--config-file', '--cache-dir',
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

export function resolveLocalPath(server: MCPServerEntry): string | undefined {
  if (!server.command) return undefined;

  const cmd = server.command;
  const args = server.args ?? [];

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

  // Direct path execution
  if (cmd.startsWith('/') || cmd.startsWith('./') || cmd.startsWith('../')) {
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

async function readSourceFile(filePath: string, fs: FSProvider): Promise<string | undefined> {
  try {
    const content = await fs.readFile(filePath);
    return content;
  } catch {
    return undefined;
  }
}

async function findMainEntry(dir: string, fs: FSProvider): Promise<string | undefined> {
  // Check package.json main field
  const pkgPath = join(dir, 'package.json');
  if (await fs.access(pkgPath)) {
    try {
      const pkg = JSON.parse(await fs.readFile(pkgPath));
      if (pkg.main) return join(dir, pkg.main);
      if (pkg.bin) {
        const binEntry = typeof pkg.bin === 'string' ? pkg.bin : Object.values(pkg.bin)[0];
        if (binEntry) return join(dir, binEntry as string);
      }
    } catch {
      // Fall through
    }
  }

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
  npmFetcher?: (spec: string) => Promise<string | undefined>;
}

function isNpmCommand(cmd?: string): boolean {
  return cmd === 'npx' || cmd === 'npx.cmd';
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

    if (localPath) {
      sourceCode = await readSourceFile(localPath, provider);

      // If it's a directory, find the main entry
      if (!sourceCode) {
        const entry = await findMainEntry(localPath, provider);
        if (entry) {
          sourceCode = await readSourceFile(entry, provider);
        }
      }
    }

    // Opt-in: resolve npm-packaged servers so their source feeds the AST/tool
    // checks. Download-only, never executed (see package-fetcher).
    if (!sourceCode && packageName && options.resolvePackages && isNpmCommand(server.command)) {
      const fetcher =
        options.npmFetcher ??
        ((spec: string) => resolveNpmPackageSource(spec, { cacheDir: options.cacheDir }));
      sourceCode = await fetcher(packageName);
    }

    const source: MCPServerSource = {
      serverName: server.name,
      packageName,
      localPath,
      sourceCode,
    };
    if (sourceCode && sourceLanguage(server, localPath, sourceCode) === 'python') {
      source.language = 'python';
    }
    sources.push(source);
  }

  return sources;
}
