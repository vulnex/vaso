import { basename, dirname, extname, join, relative, resolve } from 'node:path';
import type { MCPDataFile, MCPServerEntry, MCPServerSource } from './types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { packageExtractDir, resolveNpmPackageSource } from './package-fetcher.js';
import { collectServerDependencies } from './server-dependencies.js';
import { parse as parseTOML } from 'smol-toml';

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
    // A native executable (a Mach-O / ELF server binary launched by path) is
    // not source: read as text, its bytes match "invisible character" and
    // "encoded string" patterns everywhere.
    if (content.slice(0, 8192).includes('\u0000')) return undefined;
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

    if (localPath) {
      sourceCode = await readSourceFile(localPath, provider);
      if (sourceCode) entryFile = localPath;

      // If it's a directory, find the main entry
      if (!sourceCode) {
        const entry = await findMainEntry(localPath, provider);
        if (entry) {
          sourceCode = await readSourceFile(entry, provider);
          if (sourceCode) entryFile = entry;
        }
      }
    }

    // Opt-in: resolve npm-packaged servers so their source feeds the AST/tool
    // checks. Download-only, never executed (see package-fetcher).
    let packageDir: string | undefined;
    if (!sourceCode && packageName && options.resolvePackages && isNpmCommand(server.command)) {
      const fetcher =
        options.npmFetcher ??
        ((spec: string) => resolveNpmPackageSource(spec, { cacheDir: options.cacheDir }));
      sourceCode = await fetcher(packageName);
      if (sourceCode) packageDir = packageExtractDir(packageName, options.cacheDir);
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
const SOURCE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.py']);
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

/**
 * The server code in a directory without a declared entry: its top-level
 * source files that use the MCP SDK (or all of them when none says so).
 */
async function serverFilesIn(dir: string, fs: FSProvider): Promise<string[]> {
  let names: string[];
  try {
    names = await fs.readdir(dir);
  } catch {
    return [];
  }
  const candidates = names.filter((n) => SOURCE_EXTENSIONS.has(extname(n).toLowerCase())).sort().map((n) => join(dir, n));
  const usingSdk: string[] = [];
  for (const file of candidates) {
    const code = await readSourceFile(file, fs);
    if (code && MCP_SDK_REFERENCE.test(code)) usingSdk.push(file);
  }
  return usingSdk.length > 0 ? usingSdk : candidates;
}

/** Directories inside a Python package that are not server code. */
const PY_SKIP_DIRS = new Set(['tests', 'test', '__pycache__', '.venv', 'venv', 'node_modules', '.git', 'build', 'dist', 'site-packages']);
const MAX_PY_PACKAGE_FILES = 200;

/** Every module of a Python package directory, entry-relevant first, tests and caches skipped. */
async function pythonModules(pkgDir: string, fs: FSProvider): Promise<string[]> {
  const files: string[] = [];
  const pending = [pkgDir];
  for (let dir = pending.shift(); dir !== undefined && files.length < MAX_PY_PACKAGE_FILES; dir = pending.shift()) {
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
  return files.sort((a, b) => rank(a) - rank(b)).slice(0, MAX_PY_PACKAGE_FILES);
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
      if (!(await fs.access(join(pkg, '__init__.py'))) && !(await fs.access(join(pkg, '__main__.py')))) continue;
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
  /** Paths that don't exist or hold no readable server source. */
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
    try {
      const st = await fs.stat(path);
      if (st.isFile()) files = [path];
      else if (st.isDirectory()) {
        const entry = await findMainEntry(path, fs);
        files = entry ? [entry] : await serverFilesIn(path, fs);
        // A Python package checkout (pyproject + src/<pkg>/): all its modules
        if (!entry && (files.length === 0 || files.every((f) => f.endsWith('.py')))) {
          const pkgFiles = await pythonPackageFiles(path, fs);
          if (pkgFiles) files = pkgFiles;
        }
      }
    } catch {
      // reported below
    }

    const parts: string[] = [];
    for (const file of files) {
      const code = await readSourceFile(file, fs);
      if (code !== undefined) parts.push(files.length > 1 ? `// === ${relative(path, file) || basename(file)} ===\n${code}` : code);
    }
    if (parts.length === 0) {
      unreadable.push(given);
      continue;
    }

    const sourceCode = parts.join('\n\n');
    const entryFile = files[0];
    const source: MCPServerSource = { serverName: basename(path), localPath: entryFile, sourceCode };
    if (parts.length > 1) source.sourceRoot = path;
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
