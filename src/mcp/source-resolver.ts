import { basename, dirname, extname, isAbsolute, join, relative, resolve } from 'node:path';
import type { MCPDataFile, MCPServerEntry, MCPServerSource } from './types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { fetchNpmPackageSource, packageExtractDir, type PackageFetchResult } from './package-fetcher.js';
import { collectServerDependencies } from './server-dependencies.js';
import { parse as parseTOML } from 'smol-toml';
import { binaryFileFormat, binaryFormat, isScriptFile, sourceText } from '../analyzers/binary-text.js';
import { readCappedFile, ScanLimitError } from '../core/file-limits.js';
import { isExcludedPath, relEscapes } from '../core/utils.js';
import { isTestPath } from '../analyzers/test-paths.js';
import { shellLaunchTarget } from './shell-launch.js';
import { commandWords, MAX_SCRIPT_CHARS, scriptCommands } from './script-command.js';
import { parseJsonLenient } from '../core/jsonc.js';

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
const PYTHON_VALUE_FLAGS = new Set(['-W', '-X', '-Q', '--check-hash-based-pycs']);

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
export function uvRunScript(args: string[], base?: string): string | undefined {
  let directory: string | undefined = base;
  let afterRun = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--directory' || arg === '--project') {
      const dir = args[++i] ?? '';
      directory = base ? resolve(base, dir) : dir;
      continue;
    }
    if (arg.startsWith('--directory=')) {
      const dir = arg.slice('--directory='.length);
      directory = base ? resolve(base, dir) : dir;
      continue;
    }
    if (UV_VALUE_FLAGS.has(arg)) { i++; continue; }
    if (arg.startsWith('-')) continue;
    if (!afterRun) {
      if (arg !== 'run') return undefined; // `uv tool run`, `uv pip …` — not a script
      afterRun = true;
      continue;
    }
    // a URL is fetched, not a file of this checkout (uvRunRemote)
    if (/^https?:\/\//i.test(arg)) return undefined;
    // First `.py` positional after `run`: covers `run server.py`,
    // `run python server.py` and `run mcp run server.py`.
    if (arg.endsWith('.py')) return directory ? resolve(directory, arg) : resolve(arg);
  }
  return undefined;
}

/**
 * The module a `uv … run -m <module>` or `uv … run python -m <module>`
 * invocation runs, and the directory it runs in (`--directory`, else the
 * config's cwd; unknown when neither is given or the directory is relative
 * to an unknown cwd).
 */
export function uvRunModule(args: string[], base?: string): { module: string; directory?: string } | undefined {
  let directory: string | undefined = base;
  let afterRun = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    let dir: string | undefined;
    if (arg === '--directory' || arg === '--project') dir = args[++i] ?? '';
    else if (arg.startsWith('--directory=')) dir = arg.slice('--directory='.length);
    if (dir !== undefined) {
      directory = base ? resolve(base, dir) : isAbsolute(dir) ? resolve(dir) : undefined;
      continue;
    }
    if (UV_VALUE_FLAGS.has(arg)) { i++; continue; }
    if (afterRun && (arg === '-m' || arg === '--module')) {
      const module = args[i + 1];
      return module && !module.startsWith('-') ? { module, ...(directory ? { directory } : {}) } : undefined;
    }
    if (arg.startsWith('-')) continue;
    if (!afterRun) {
      if (arg !== 'run') return undefined;
      afterRun = true;
      continue;
    }
    // `uv run python -m mod`
    if (PYTHON_INTERPRETER.test(basename(arg))) {
      const run = pythonRun(args.slice(i + 1));
      return run.module ? { module: run.module, ...(directory ? { directory } : {}) } : undefined;
    }
    return undefined;
  }
  return undefined;
}

/** Python's boolean single-letter options, combinable (`-uB`, `-Ic`). */
const PYTHON_BOOL_LETTERS = 'bBdEhiIOPqsSuvVx';
const PYTHON_COMBINED = new RegExp(`^-[${PYTHON_BOOL_LETTERS}]*([cm])(.*)$`);

/**
 * What `python [options] …` runs: a script, a module (`-m pkg`), or inline
 * code (`-c`). Options with a value (`-W`, `-X`, `--check-hash-based-pycs`)
 * are skipped with it; single-letter options combine (`-uc code`, `-Im pkg`).
 */
function pythonRun(args: string[]): { script?: string; module?: string; inline?: boolean } {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--') return args[i + 1] ? { script: args[i + 1] } : {};
    if (PYTHON_VALUE_FLAGS.has(arg)) { i++; continue; }
    const combined = PYTHON_COMBINED.exec(arg);
    if (combined) {
      const attached = combined[2];
      if (combined[1] === 'c') return { inline: true };
      const module = attached || args[i + 1];
      return module ? { module } : {};
    }
    if (arg.startsWith('-')) continue;
    return { script: arg };
  }
  return {};
}

/** The URL `uv run https://…/server.py` fetches and runs, if that is what it runs. */
function uvRunRemote(args: string[]): string | undefined {
  let afterRun = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (UV_VALUE_FLAGS.has(arg)) { i++; continue; }
    if (arg.startsWith('-')) continue;
    if (!afterRun) {
      if (arg !== 'run') return undefined;
      afterRun = true;
      continue;
    }
    return /^https?:\/\//i.test(arg) ? arg : undefined;
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

/**
 * What a server's command runs from local disk: the entry file, modules
 * preloaded into it (`node -r ./setup.js`, `--import ./register.mjs`), or a
 * package directory whose script starts it (`pnpm --dir d start`). `note`
 * says why a runner that executes local code named no file this scan can
 * read (`node -e …`, a remote `deno run https://…`).
 */
export interface LaunchTarget {
  entry?: string;
  preloads: string[];
  /** A local package directory whose package.json script (`script`) or main starts the server. */
  packageDir?: string;
  script?: string;
  note?: string;
  /** The OS runs `entry` itself (the command is the server's path): its magic bytes decide what it is. */
  executed?: boolean;
  /** `python -m <module>`: run from `moduleBase` (the working directory) when its copy is there, else an installed one. */
  module?: string;
  moduleBase?: string;
  /** `script` is a `deno task` (deno.json `tasks`, then package.json `scripts`). */
  denoTask?: boolean;
}

/**
 * Options that take the next argument as their value (`--opt value`), per
 * runtime — an option's value read as the entry analysed the wrong file, or
 * none. Options whose value is optional and given only with `=`
 * (`--inspect[=port]`) are not listed. Node: `node --help` (v24) plus V8
 * size options and options of earlier releases (`--experimental-policy`).
 */
const NODE_VALUE_FLAGS = new Set([
  '-r', '--require', '--import', '--loader', '--experimental-loader', '--env-file', '--env-file-if-exists',
  '-C', '--conditions', '--input-type', '--title', '--inspect-port', '--debug-port', '--redirect-warnings',
  '--report-dir', '--report-directory', '--report-filename', '--report-signal', '--diagnostic-dir',
  '--cpu-prof-dir', '--cpu-prof-name', '--cpu-prof-interval', '--heap-prof-dir', '--heap-prof-name', '--heap-prof-interval',
  '--openssl-config', '--icu-data-dir', '--tls-cipher-list', '--tls-keylog', '--secure-heap', '--secure-heap-min',
  '--disable-warning', '--disable-proto', '--watch-path', '--watch-kill-signal', '--experimental-config-file',
  '--max-old-space-size', '--max-old-space-size-percentage', '--max-semi-space-size', '--stack-size', '--stack-trace-limit',
  '--unhandled-rejections', '--dns-result-order', '--experimental-default-type', '--localstorage-file', '--snapshot-blob',
  '--build-snapshot-config', '--experimental-sea-config', '--allow-fs-read', '--allow-fs-write',
  '--experimental-policy', '--policy-integrity', '--heapsnapshot-near-heap-limit', '--heapsnapshot-signal',
  '--max-http-header-size', '--trace-event-categories', '--trace-event-file-pattern', '--trace-require-module',
  '--inspect-publish-uid', '--network-family-autoselection-attempt-timeout', '--use-largepages', '--v8-pool-size',
  '--test-reporter', '--test-reporter-destination', '--test-concurrency', '--test-name-pattern', '--test-skip-pattern',
  '--test-shard', '--test-timeout', '--test-isolation', '--experimental-test-isolation', '--test-global-setup',
  '--test-random-seed', '--test-rerun-failures', '--test-coverage-branches', '--test-coverage-functions',
  '--test-coverage-lines', '--test-coverage-include', '--test-coverage-exclude', '--run',
]);
/** tsx / ts-node: node's options plus their own. */
const TS_VALUE_FLAGS = new Set([
  ...NODE_VALUE_FLAGS,
  '--tsconfig', '--ignore', '--include', '--exclude',
  '-P', '--project', '-O', '--compiler-options', '--compiler', '-D', '--ignore-diagnostics', '-I',
  '--cwd', '--dir', '--scope-dir',
]);
/** bun (`bun --help`, 1.3) plus its bundler options accepted by `bun run`. */
const BUN_VALUE_FLAGS = new Set([
  '-r', '--preload', '--require', '--import', '--cpu-prof-name', '--cpu-prof-dir', '--cpu-prof-interval',
  '--heap-prof-name', '--heap-prof-dir', '--install', '--port', '--conditions', '--fetch-preconnect',
  '--max-http-header-size', '--dns-result-order', '--title', '--unhandled-rejections', '--console-depth',
  '--user-agent', '--elide-lines', '-F', '--filter', '--shell', '--env-file', '--cwd', '-c', '--config',
  '--tsconfig-override', '--main-fields', '-d', '--define', '-l', '--loader',
]);
type NodeRuntime = 'node' | 'ts' | 'bun';
const VALUE_FLAGS: Record<NodeRuntime, Set<string>> = { node: NODE_VALUE_FLAGS, ts: TS_VALUE_FLAGS, bun: BUN_VALUE_FLAGS };
/** Options whose value is a module loaded before the entry. */
const NODE_PRELOAD_FLAGS = new Set(['-r', '--require', '--import', '--loader', '--experimental-loader', '--preload']);
/** Options that run code given on the command line instead of a file. */
const NODE_INLINE_FLAGS = new Set(['-e', '--eval', '-p', '--print']);
/** deno options that take the next argument as their value. */
const DENO_VALUE_FLAGS = new Set(['--config', '-c', '--import-map', '--lock', '--cert', '--location', '--seed', '--ext', '--watch-exclude', '--preload']);

/** A module specifier that is a file on disk, not a package (`dotenv/config`, `tsx`). */
function isLocalSpecifier(spec: string): boolean {
  return /^(?:\.{1,2}[\\/]|[\\/]|[A-Za-z]:[\\/]|file:)/.test(spec);
}

function localFile(spec: string, base: string | undefined): string {
  const path = spec.startsWith('file://') ? decodeURIComponent(spec.slice('file://'.length)) : spec.replace(/^file:/, '');
  return base ? resolve(base, path) : resolve(path);
}

/**
 * Inline code that only loads a local file — `import('./server.js')`,
 * `require("./dist/index.js")`, `import "./x.mjs"` — names that file.
 */
const INLINE_LOAD = /^\s*(?:await\s+)?(?:import\s*\(\s*(["'`])([^"'`\n]+)\1\s*\)|require\s*\(\s*(["'`])([^"'`\n]+)\3\s*\)|import\s+(["'])([^"'\n]+)\5)\s*;?\s*$/;
function inlineLoadedFile(code: string | undefined): string | undefined {
  const m = code === undefined ? null : INLINE_LOAD.exec(code);
  const spec = m ? (m[2] ?? m[4] ?? m[6]) : undefined;
  return spec && isLocalSpecifier(spec) ? spec : undefined;
}

/** An argument that reads as a script path, not an option's value (`delete`, `16384`, `v8`). */
function looksLikeScript(arg: string): boolean {
  return SCRIPT_FILE.test(arg) || /[\\/]/.test(arg) || isLocalSpecifier(arg);
}

interface NodeStyleParse extends LaunchTarget {
  /** The first positional argument, as written. */
  positional?: string;
  /** The working directory after `--cwd`; `cwdKnown` when the config pins it (its `cwd`, an absolute `--cwd`). */
  cwdKnown?: boolean;
  cwd?: string;
}

/**
 * The script a node-style runner (node, tsx, ts-node, bun) executes: the
 * first positional argument, past option values (`-r dotenv/config`,
 * `--env-file .env`, `--max-old-space-size 4096`), with local preloads
 * collected on the way. An option this table doesn't know, followed by a word
 * that is no script (`--some-flag value server.js`), is read as taking it.
 */
function nodeStyleTarget(args: string[], base: string | undefined, runtime: NodeRuntime, subcommands: Set<string> = new Set()): NodeStyleParse {
  const preloads: string[] = [];
  const valueFlags = VALUE_FLAGS[runtime];
  let cwd = base;
  let cwdKnown = base !== undefined;
  let afterUnknownFlag = false;
  let lastPositional = -1;
  for (let j = args.length - 1; j >= 0 && lastPositional < 0; j--) if (!args[j].startsWith('-')) lastPositional = j;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--') {
      const next = args[i + 1];
      return next ? { entry: localFile(next, cwd), preloads, positional: next, cwd } : { preloads, note: 'no script file in its arguments' };
    }
    if (arg === '-') return { preloads, note: 'reads its code from stdin' };
    const inline = /^(-{1,2}[\w-]+)=(.*)$/.exec(arg);
    const flag = inline ? inline[1] : arg;
    if (NODE_INLINE_FLAGS.has(flag)) {
      const code = inline ? inline[2] : args[i + 1];
      const loaded = inlineLoadedFile(code);
      if (loaded) return { entry: localFile(loaded, cwd), preloads, cwd };
      return { preloads, note: `runs inline code (${flag})` };
    }
    if (runtime === 'node' && (flag === '-c' || flag === '--check')) return { preloads, note: `only checks syntax (${flag})` };
    if (arg.startsWith('-')) {
      if (!valueFlags.has(flag)) {
        afterUnknownFlag = !inline && arg.startsWith('--');
        continue;
      }
      afterUnknownFlag = false;
      const value = inline ? inline[2] : args[++i];
      if (value === undefined) continue;
      if (flag === '--cwd') { cwd = cwd ? resolve(cwd, value) : resolve(value); cwdKnown ||= isAbsolute(value); }
      else if (flag === '--run' && runtime === 'node') return { preloads, script: value, cwd, ...(cwd && cwdKnown ? { packageDir: cwd } : { note: noWorkingDir(value) }) };
      else if (NODE_PRELOAD_FLAGS.has(flag) && isLocalSpecifier(value)) preloads.push(localFile(value, cwd));
      continue;
    }
    if (subcommands.has(arg)) { afterUnknownFlag = false; continue; }
    // `--unknown-option value script.js`, `node --flag 3 x.js`: the word is the option's
    if ((afterUnknownFlag || /^\d+$/.test(arg)) && !looksLikeScript(arg) && i < lastPositional) {
      afterUnknownFlag = false;
      continue;
    }
    return { entry: localFile(arg, cwd), preloads, positional: arg, cwd, cwdKnown };
  }
  return { preloads, note: 'no script file in its arguments', cwd };
}

/** Why a package script in an unknown directory is not read. */
function noWorkingDir(script: string): string {
  return `runs package script "${script}" in the client's working directory, which the config does not set`;
}

/** Packages that run a local file (`npx -y tsx@4 server.ts`). */
const FILE_RUNNER_PACKAGES = new Set(['tsx', 'ts-node', 'esno', 'bun']);

/** A file a JS/TS runner executes, not a package.json script name. */
const SCRIPT_FILE = /\.(?:[mc]?[jt]s|[jt]sx)$/i;

/** bun subcommands that install or fetch packages, not run a script. */
const BUN_PACKAGE_COMMANDS = new Set(['x', 'add', 'install', 'i', 'create', 'init', 'pm', 'link', 'remove', 'update', 'upgrade', 'outdated', 'publish', 'patch']);

/** `fastmcp run` / `mcp run|dev` options that take a value. */
const PY_MCP_VALUE_FLAGS = new Set([
  '--transport', '-t', '--host', '--port', '-p', '--path', '--log-level', '-l', '--python', '--with',
  '--with-editable', '-e', '--with-requirements', '--project', '--server-spec', '--name', '-n', '--env-file', '-f', '-v', '--env-var',
]);

export function launchTarget(server: MCPServerEntry): LaunchTarget {
  const none: LaunchTarget = { preloads: [] };
  if (!server.command) return none;

  const cmd = server.command;
  const args = server.args ?? [];
  const base = server.cwd ? resolve(server.cwd) : undefined;
  const runner = runnerName(cmd).toLowerCase();
  const strip = ({ positional: _p, cwd: _c, cwdKnown: _k, ...target }: NodeStyleParse): LaunchTarget => target;

  // A package runner fetches and runs a published package, not a local file —
  // unless that package is a script runner (`npx -y tsx server.ts`)
  if (PACKAGE_RUNNERS.has(runner)) {
    if (runner === 'npx' || runner === 'bunx' || runner === 'pnpx') {
      const spec = inferPackageName(server);
      const name = spec?.replace(/(?!^)@[^/]*$/, '');
      if (spec && name && FILE_RUNNER_PACKAGES.has(name)) {
        return strip(nodeStyleTarget(args.slice(args.indexOf(spec) + 1), base, name === 'bun' ? 'bun' : 'ts', new Set(['watch'])));
      }
    }
    return none;
  }

  // Interpreter + script, also when the interpreter is given by path — an
  // absolute nvm `node` or venv `python` is the norm in desktop configs, and
  // reading the interpreter binary as "server source" analyzed nothing.
  switch (interpreterOf(cmd)) {
    case 'node':
      return strip(nodeStyleTarget(args, base, 'node'));
    case 'python': {
      const run = pythonRun(args);
      if (run.script) return { entry: localFile(run.script, base), preloads: [] };
      // `python -m pkg` runs a module: the working directory's copy when there is one, else an installed one
      if (run.module) return { preloads: [], module: run.module, ...(base ? { moduleBase: base } : {}) };
      return { preloads: [], note: run.inline ? 'runs inline code (-c)' : 'no script file in its arguments' };
    }
    case 'uv': {
      const remote = uvRunRemote(args);
      if (remote) return { preloads: [], note: `runs a remote script (${remote})` };
      const script = uvRunScript(args, base);
      if (script) return { entry: script, preloads: [] };
      const module = uvRunModule(args, base);
      return module ? { preloads: [], module: module.module, ...(module.directory ? { moduleBase: module.directory } : {}) } : none;
    }
  }

  switch (runner) {
    case 'tsx':
    case 'ts-node':
    case 'ts-node-esm':
    case 'esno':
      return strip(nodeStyleTarget(args, base, 'ts', new Set(['watch'])));
    case 'bun': {
      const target = nodeStyleTarget(args, base, 'bun', new Set(['run']));
      const positional = target.positional;
      // `bun run start` runs a package.json script; `bun x pkg` / `bun add` are package commands
      if (target.entry && positional && !SCRIPT_FILE.test(positional) && !isLocalSpecifier(positional)) {
        if (BUN_PACKAGE_COMMANDS.has(positional)) return none;
        return target.cwd && target.cwdKnown
          ? { preloads: target.preloads, packageDir: target.cwd, script: positional }
          : { preloads: target.preloads, note: noWorkingDir(positional) };
      }
      return strip(target);
    }
    case 'deno': {
      const task = denoTask(args);
      if (task) {
        const dir = task.dir ? (base ? resolve(base, task.dir) : isAbsolute(task.dir) ? resolve(task.dir) : undefined) : base;
        return dir ? { preloads: [], packageDir: dir, script: task.name, denoTask: true } : { preloads: [], note: noWorkingDir(task.name) };
      }
      const target = denoRunTarget(args);
      if (!target) return none;
      if (/^https?:/i.test(target)) return { preloads: [], note: `runs a remote module (${target})` };
      if (/^(?:npm|jsr):/i.test(target)) return none;
      return { entry: localFile(target, base), preloads: [] };
    }
    case 'fastmcp':
    case 'mcp': {
      // `fastmcp run [--transport stdio] server.py[:app]`, `mcp run server.py`
      if (args[0] !== 'run' && args[0] !== 'dev') return none;
      let file: string | undefined;
      for (let i = 1; i < args.length; i++) {
        const arg = args[i];
        if (arg === '--') continue;
        if (arg.startsWith('-')) {
          if (!arg.includes('=') && PY_MCP_VALUE_FLAGS.has(arg)) i++;
          continue;
        }
        if (/^https?:/i.test(arg)) return { preloads: [], note: `runs a remote server (${arg})` };
        file = arg;
        break;
      }
      if (!file) return { preloads: [], note: 'no script file in its arguments' };
      const path = file.replace(/:[A-Za-z_][\w.]*$/, '');
      if (/\.py$/i.test(path)) return { entry: localFile(path, base), preloads: [] };
      return { preloads: [], note: `runs ${basename(path)}, not a Python file` };
    }
    case 'npm':
    case 'pnpm':
    case 'yarn': {
      const run = packageScriptRun(args, runner);
      if (!run) return none;
      const dir = run.dir ? (base ? resolve(base, run.dir) : isAbsolute(run.dir) ? resolve(run.dir) : undefined) : base;
      return dir ? { preloads: [], packageDir: dir, script: run.script } : { preloads: [], note: noWorkingDir(run.script) };
    }
  }

  // Direct path execution — of the server itself, not a launcher that runs
  // something else (`/usr/bin/env npx …`, `/bin/bash -c`, `docker run`)
  if ((cmd.startsWith('/') || cmd.startsWith('./') || cmd.startsWith('../')) && !LAUNCHERS.has(runner)) {
    return { entry: base && !cmd.startsWith('/') ? resolve(base, cmd) : resolve(cmd), preloads: [], executed: true };
  }

  return none;
}

/** `deno task [--cwd d] [--config f] name`: the task and the directory it runs in. */
function denoTask(args: string[]): { name: string; dir?: string } | undefined {
  let sawTask = false;
  let dir: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const inline = /^(--[\w-]+)=(.*)$/.exec(arg);
    if (!sawTask) {
      if (arg.startsWith('-')) continue;
      if (arg !== 'task') return undefined;
      sawTask = true;
      continue;
    }
    if (inline && inline[1] === '--cwd') { dir = inline[2]; continue; }
    if (arg === '--cwd') { dir = args[++i]; continue; }
    if (arg === '--config' || arg === '-c' || arg === '--filter' || arg === '-f') { i++; continue; }
    if (arg.startsWith('-')) continue;
    return { name: arg, dir };
  }
  return undefined;
}

/**
 * The module `deno run|serve [flags] <module>` executes (a path, URL or
 * `npm:`/`jsr:` specifier); undefined for other subcommands (`deno task`).
 */
export function denoRunTarget(args: string[]): string | undefined {
  let sub: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('-')) {
      if (sub && DENO_VALUE_FLAGS.has(arg)) i++;
      continue;
    }
    if (!sub) {
      if (arg !== 'run' && arg !== 'serve') return undefined;
      sub = arg;
      continue;
    }
    return arg;
  }
  return undefined;
}

/** npm/pnpm/yarn options naming the package directory, and other options that take a value. */
const PM_DIR_FLAGS = new Set(['--dir', '-C', '--cwd', '--prefix']);
const PM_VALUE_FLAGS = new Set(['--filter', '-F', '--workspace', '-w', '--userconfig', '--cache', '--registry']);

/**
 * `pnpm --dir d start`, `yarn --cwd d run serve`, `npm --prefix d start`:
 * the package directory and the script name. Undefined for installs and
 * package fetches (`dlx`, `exec`, `x`). npm reads its own options after the
 * script name too (`npm run start --prefix d`, up to `--`); pnpm and yarn
 * pass them to the script.
 */
export function packageScriptRun(args: string[], runner = 'npm'): { dir?: string; script: string } | undefined {
  let dir: string | undefined;
  let sawRun = false;
  let script: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (script !== undefined && (runner !== 'npm' || arg === '--')) break;
    const inline = /^(--[\w-]+)=(.*)$/.exec(arg);
    if (inline && PM_DIR_FLAGS.has(inline[1])) { dir = inline[2]; continue; }
    if (PM_DIR_FLAGS.has(arg)) { dir = args[++i]; continue; }
    if (PM_VALUE_FLAGS.has(arg)) { i++; continue; }
    if (arg.startsWith('-')) continue;
    if (script !== undefined) continue;
    if (!sawRun && (arg === 'run' || arg === 'run-script')) { sawRun = true; continue; }
    if (!sawRun && ['dlx', 'exec', 'x', 'add', 'install', 'i', 'ci', 'create', 'init', 'link'].includes(arg)) return undefined;
    script = arg;
  }
  return script === undefined ? undefined : { dir, script };
}

/** The entry file of `launchTarget`. */
export function resolveLocalPath(server: MCPServerEntry): string | undefined {
  return launchTarget(server).entry;
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

/** How deep package scripts calling package scripts (`"start": "npm run serve"`) are followed. */
const MAX_SCRIPT_DEPTH = 4;
/** Shells whose `-c` command a script runs. */
const SCRIPT_SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh']);

/** The text of a package's `name` script: package.json `scripts`, or deno.json(c) `tasks` for `deno task`. */
async function readPackageScript(dir: string, name: string, fs: FSProvider, deno: boolean): Promise<{ found: boolean; line?: string }> {
  if (deno) {
    for (const file of ['deno.json', 'deno.jsonc']) {
      const text = await fs.readFile(join(dir, file)).catch(() => undefined);
      if (text === undefined) continue;
      let config: { tasks?: Record<string, unknown> } | undefined;
      try {
        config = parseJsonLenient(text) as { tasks?: Record<string, unknown> };
      } catch {
        continue;
      }
      const task = config?.tasks?.[name];
      const line = typeof task === 'string' ? task : typeof (task as { command?: unknown })?.command === 'string' ? (task as { command: string }).command : undefined;
      if (line !== undefined) return { found: true, line };
    }
  }
  let pkg: { scripts?: Record<string, unknown> } | undefined;
  try {
    pkg = JSON.parse(await fs.readFile(join(dir, 'package.json')));
  } catch {
    return { found: false };
  }
  const line = pkg?.scripts?.[name];
  return { found: true, ...(typeof line === 'string' ? { line } : {}) };
}

/**
 * What `<pm> run <script>` in a local package starts: the file the
 * package.json script runs (`"start": "node dist/index.js"`), read with the
 * same launcher rules as a config command — through `&&` chains, nested
 * `npm run x`, `sh -c '…'`, `node -e "import('./x.js')"`, `python -m mod`.
 * With no such script, the package directory, whose declared entry
 * findMainEntry() picks (npm's default `start` runs `server.js`, one of its
 * candidates). A script whose command this scan can't follow is noted, not
 * replaced by the package's main.
 */
async function packageScriptEntry(
  dir: string,
  script: string | undefined,
  fs: FSProvider,
  options: { deno?: boolean; depth?: number } = {},
): Promise<ScriptEntry> {
  const depth = options.depth ?? 0;
  const read = script ? await readPackageScript(dir, script, fs, options.deno === true) : { found: (await fs.access(join(dir, 'package.json'))) };
  if (!read.found) {
    return (await fs.stat(dir).then((st) => st.isDirectory(), () => false))
      ? { path: dir }
      : { note: `package directory ${dir} not found` };
  }
  if (read.line === undefined || !script) return { path: dir };
  return scriptLineEntry(dir, script, read.line, fs, depth);
}

/**
 * The commands of a script longer than the cap: those wholly inside it, and
 * the one it cuts without its last (possibly cut) word — `node evil.js`
 * followed by padding is still `node evil.js`.
 */
function cutScriptCommands(text: string): string[] {
  const head = text.slice(0, MAX_SCRIPT_CHARS);
  const commands = scriptCommands(head);
  const last = commands.pop();
  if (last === undefined) return commands;
  // The cut word runs to the end of the head; a word whose quote the cut
  // left open is cut too
  const quoteAt = openQuoteAt(last);
  const cutOnSpace = /\s/.test(text[MAX_SCRIPT_CHARS] ?? '') || /\s$/.test(head);
  const kept = (quoteAt >= 0 ? last.slice(0, quoteAt).replace(/\S+$/, '') : cutOnSpace ? last : last.replace(/\S+$/, '')).trimEnd();
  if (kept !== '') commands.push(kept);
  return commands;
}

/** Where the quote `command` ends inside opens, or -1. */
function openQuoteAt(command: string): number {
  let quote = '';
  let at = -1;
  for (let i = 0; i < command.length; i++) {
    const c = command[i];
    if (quote) {
      if (c === '\\' && quote === '"') i++;
      else if (c === quote) quote = '';
      continue;
    }
    if (c === '\\') { i++; continue; }
    if (c === '"' || c === "'") { quote = c; at = i; }
  }
  return quote ? at : -1;
}

/**
 * What a package script starts: `path`, the first file one of its commands
 * runs; `extra`, the files later commands run (`node check.js && node
 * dist/server.js` starts both); `partial`, why part of the script was not
 * read (the length cap, the command cap); `note`, why nothing could be
 * followed; `fallback`, a missing entry (before a build) — the package's own.
 */
interface ScriptEntry {
  path?: string;
  extra?: string[];
  partial?: string;
  note?: string;
  fallback?: boolean;
}

/** Commands of one package script whose launch targets are followed. */
const MAX_SCRIPT_COMMANDS = 16;

async function scriptLineEntry(dir: string, script: string, line: string, fs: FSProvider, depth: number): Promise<ScriptEntry> {
  if (depth >= MAX_SCRIPT_DEPTH) return { note: `package script "${script}" nests other scripts too deeply` };
  // Past the cap only the commands wholly inside it are read; of the one the
  // cap cuts, the words before the cut word (its program and entry, when the
  // cut falls in later arguments or padding)
  const text = line.trimEnd();
  const capped = text.length > MAX_SCRIPT_CHARS;
  const all = capped ? cutScriptCommands(text) : scriptCommands(text);
  const commands = all.slice(0, MAX_SCRIPT_COMMANDS);
  const partial: string | undefined = capped
    ? `package script "${script}" is longer than ${MAX_SCRIPT_CHARS / 1024} KiB and was read only in part`
    : all.length > MAX_SCRIPT_COMMANDS
      ? `package script "${script}" runs more than ${MAX_SCRIPT_COMMANDS} commands and was read only in part`
      : undefined;
  let note = partial;
  let fallback = false;
  // Every command's launch target: `node scripts/check.js && node dist/server.js` runs both
  const paths: string[] = [];
  // Why a command was not followed (`bash evil.sh`): kept even when another command is
  const unfollowed: string[] = [];
  for (const command of commands) {
    const r = await scriptCommandEntry(dir, script, command, fs, depth);
    for (const p of [r.path, ...(r.extra ?? [])]) if (p && !paths.includes(p)) paths.push(p);
    if (r.fallback) fallback = true;
    note ??= r.note ?? r.partial;
    for (const why of [r.partial, r.note]) if (why && why !== partial && !unfollowed.includes(why)) unfollowed.push(why);
  }
  // `node dist/index.js` before a build: the package's own entry or its TypeScript source
  if (fallback && !paths.includes(dir)) paths.push(dir);
  if (paths.length === 0) return { note: note ?? `package script "${script}" starts no file this scan can follow` };
  const why = [partial, ...unfollowed].filter((w): w is string => w !== undefined).join('; ');
  return { path: paths[0], ...(paths.length > 1 ? { extra: paths.slice(1) } : {}), ...(why ? { partial: why } : {}) };
}

async function scriptCommandEntry(
  dir: string,
  script: string,
  command: string,
  fs: FSProvider,
  depth: number,
): Promise<ScriptEntry> {
  const words = commandWords(command);
  if (words.length === 0) return {};
  const program = runnerName(words[0]).toLowerCase();
  const rest = words.slice(1);
  // `sh -c 'node evil.js'`
  if (SCRIPT_SHELLS.has(program)) {
    const at = rest.findIndex((w) => /^-[a-z]*c$/.test(w));
    const code = at >= 0 ? rest[at + 1] : undefined;
    if (code === undefined) return { note: `package script "${script}" runs a ${program} script` };
    return scriptLineEntry(dir, script, code, fs, depth + 1);
  }
  const inner = launchTarget({ name: script, command: words[0], args: rest, cwd: dir, transport: 'stdio' });
  if (inner.entry) {
    const interpreter = interpreterOf(words[0]);
    const python = interpreter === 'python' || interpreter === 'uv';
    // Node looks for `X`, then `X.js`, before the directory `X/` (`node server` runs server.js)
    // (`node sub/` with its slash names the directory only)
    const dirOnly = rest.some((w) => /[\\/]$/.test(w) && resolve(dir, w) === inner.entry);
    const files = python || dirOnly || /\.[cm]?[jt]sx?$/i.test(inner.entry) ? [inner.entry] : [inner.entry, `${inner.entry}.js`];
    for (const file of files.flatMap((f) => [f, ...sourceTwins(dir, f)])) {
      if (await isFile(file, fs)) return { path: file };
    }
    // `node sub`: Node runs the directory's package.json main, else its
    // index.js; `python3 sub` runs its __main__.py
    if (await fs.stat(inner.entry).then((st) => st.isDirectory(), () => false)) {
      const main = join(inner.entry, '__main__.py');
      const file = python ? ((await isFile(main, fs)) ? main : undefined) : await directoryEntry(inner.entry, fs);
      return file ? { path: file } : { note: `package script "${script}" runs the directory ${inner.entry}, which has no ${python ? '__main__.py' : 'entry file'}` };
    }
    return { fallback: true, note: `package script "${script}" runs ${inner.entry}, which is not there — the package's own entry was analysed instead` };
  }
  if (inner.packageDir) {
    const nested = await packageScriptEntry(inner.packageDir, inner.script, fs, { deno: inner.denoTask, depth: depth + 1 });
    return nested;
  }
  if (inner.module) {
    const file = await pythonModuleFile(inner.module, inner.moduleBase ?? dir, fs);
    return file ? { path: file } : { note: `package script "${script}" runs the installed Python module ${inner.module}` };
  }
  if (inner.note) return { note: `package script "${script}" ${inner.note}` };
  // build steps (`tsc`, `rimraf dist`) before the server starts: the next command decides
  return {};
}

/** The file Node loads for a directory: its package.json `main` (as a file, `.js` or a directory index), else index.js. */
async function directoryEntry(entryDir: string, fs: FSProvider): Promise<string | undefined> {
  let main: unknown;
  try {
    main = (JSON.parse(await fs.readFile(join(entryDir, 'package.json'))) as { main?: unknown }).main;
  } catch {
    main = undefined;
  }
  const candidates = typeof main === 'string' && main !== ''
    ? [join(entryDir, main), `${join(entryDir, main)}.js`, join(entryDir, main, 'index.js')]
    : [];
  for (const file of [...candidates, join(entryDir, 'index.js')]) if (await isFile(file, fs)) return file;
  return undefined;
}

/** The file `python -m <module>` runs from `base` (its own package, not an installed one), if there. */
async function pythonModuleFile(module: string, base: string, fs: FSProvider): Promise<string | undefined> {
  if (!/^[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*$/.test(module)) return undefined;
  const rel = module.split('.');
  for (const root of [base, join(base, 'src')]) {
    for (const file of [join(root, ...rel) + '.py', join(root, ...rel, '__main__.py')]) {
      if (await isFile(file, fs)) return file;
    }
  }
  return undefined;
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
    const target = launchTarget(server);
    // Why a runner of local code left nothing to analyze (MCP-001 lists it)
    let unanalyzed = target.note;
    let localPath = target.entry;
    // Files later commands of the package script start, and why part of it was not read
    let scriptExtras: string[] = [];
    let scriptPartial: SkippedFile | undefined;
    if (!localPath && target.packageDir) {
      const started = await packageScriptEntry(target.packageDir, target.script, provider, { deno: target.denoTask });
      localPath = started.path;
      unanalyzed ??= started.note;
      scriptExtras = started.extra ?? [];
      if (started.partial && started.path) scriptPartial = { path: target.packageDir, reason: started.partial };
    }
    // `python -m pkg` in a checkout runs its own copy; an installed module is not on this disk to read
    if (!localPath && target.module && target.moduleBase) localPath = await pythonModuleFile(target.module, target.moduleBase, provider);
    if (!localPath && target.module) {
      unanalyzed ??= target.moduleBase
        ? `runs the installed Python module ${target.module}`
        : `runs the Python module ${target.module} from the client's working directory, which the config does not set, or an installed copy`;
    }

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
      const executed = target.executed === true;
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
      // The command names a file that isn't there (a moved checkout, a typo):
      // the server can't start as configured, and nothing was analyzed
      if (!sourceCode && !compiledBinary && !readFailure) {
        unanalyzed ??= (await provider.stat(localPath).then((st) => st.isDirectory(), () => undefined)) === undefined
          ? `entry file ${localPath} not found`
          : `no entry file found in ${localPath}`;
      }
    }
    // node loads its preloads (`-r ./setup.js`, `--import`) before it looks
    // for the entry: with the entry missing or inline (`-e`) they still run,
    // and are what this scan analyzes
    if (!sourceCode && !compiledBinary && !readFailure && target.preloads.length > 0) {
      for (const preload of target.preloads) {
        const code = await readSourceFile(preload, provider, (message) => hidden.push({ path: preload, reason: message }));
        if (code) {
          sourceCode = code;
          entryFile = preload;
          break;
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
      // Local modules preloaded into the entry (`node -r ./setup.js`) run as part of the server
      for (const preload of language === 'python' ? [] : target.preloads) {
        const code = await readSourceFile(preload, provider, (message) => hidden.push({ path: preload, reason: message }));
        if (!code) continue;
        for (const file of await withLocalImports(preload, code, provider, undefined, hidden)) {
          if (!files.includes(file)) files.push(file);
        }
      }
      // What later commands of the package script start runs as part of the server too
      for (const extra of scriptExtras.slice(0, MAX_SCRIPT_COMMANDS)) {
        const file = (await isFile(extra, provider)) ? extra : await findMainEntry(extra, provider);
        if (!file || files.includes(file)) continue;
        if (file.endsWith('.py') !== (language === 'python')) {
          hidden.push({ path: file, reason: `${file}: also started by the package script, in another language than its first file — not analyzed` });
          continue;
        }
        const code = await readSourceFile(file, provider, (message) => hidden.push({ path: file, reason: message }));
        if (!code) continue;
        const more = language === 'python' ? await withPythonPackage(file, provider, hidden) : await withLocalImports(file, code, provider, undefined, hidden);
        for (const f of more) if (!files.includes(f)) files.push(f);
      }
      if (files.length > 1) {
        const root = language === 'python' ? dirname(entryFile) : await serverRoot(entryFile, provider);
        const read = await readServerFiles(files, root, provider, new Map([[entryFile, sourceCode]]));
        sourceCode = read.code;
        if (read.marked) sourceRoot = root;
        hidden.push(...read.skipped);
      }
    }
    if (scriptPartial && sourceCode) hidden.push(scriptPartial);
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
      ...(unanalyzed && !sourceCode && !compiledBinary && !readFailure && !resolveFailure ? { unanalyzed } : {}),
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
      if (relEscapes(rel) || isExcludedPath(base, dirname(path), { keepBuildOutput: true })) continue;
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
