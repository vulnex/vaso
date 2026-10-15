import { basename } from 'node:path';

/**
 * What a package-runner command installs, and how firmly it is pinned. One
 * parser for every "unpinned MCP server" check (CC-005, CD-003, CDX-004,
 * OPC-003, GEM-007, QC-006, DEV-004, WS-004, HM-010, AT-007, ABA-006, MCP-010):
 * each used to take the first non-flag argument as the package, which read
 * `pnpm dlx pkg@1.2.3` as "dlx", `pipx run pkg==1` as "run", and treated
 * `uvx --from pkg==1.2.3 cmd` (uv's documented exact pin) as unpinned.
 *
 * Runners: npx, bunx, pnpx, `pnpm dlx`, `yarn dlx`, `npm exec`/`npm x`,
 * uvx, `uv tool run`, `pipx run`.
 */

export type PinKind =
  /** An exact version, a commit-pinned git URL, or a content hash. */
  | 'exact'
  /** A version range (`^1.2`, `>=1.0`, `~=1.4`, `1.x`). */
  | 'range'
  /** A moving dist-tag (`@latest`, `@next`). */
  | 'tag'
  /** No version at all. */
  | 'none'
  /** A local path or file: spec — nothing is fetched. */
  | 'local';

export interface RunnerPackage {
  /** The runner as invoked (`npx`, `pnpm dlx`, `uvx`, …). */
  runner: string;
  ecosystem: 'npm' | 'pypi';
  /** The spec as written (`@scope/pkg@^1.2`, `pkg==1.0`). */
  spec: string;
  name: string;
  pin: PinKind;
}

/** A command's executable name, also when given as a path (`/usr/local/bin/npx`, `npx.cmd`). */
export function commandName(command: string): string {
  return basename(command.replace(/\\/g, '/')).replace(/\.(?:cmd|exe|ps1)$/i, '');
}

// Options that consume the next argument
const NPX_VALUE_FLAGS = new Set(['--registry', '--cache', '--userconfig', '--prefix', '-c', '--call', '--node-options', '--workspace', '-w', '--shell', '--script-shell']);
const UV_VALUE_FLAGS = new Set([
  '--directory', '--project', '--python', '-p', '--with', '--with-editable',
  '--with-requirements', '--env-file', '--index', '--index-url', '--default-index',
  '--extra-index-url', '--config-file', '--cache-dir', '--link-mode', '--index-strategy',
  '--keyring-provider', '--constraints', '--overrides', '--prerelease', '--resolution',
  '--exclude-newer', '--refresh-package', '--reinstall-package', '--upgrade-package', '--build-constraints',
]);
const PIPX_VALUE_FLAGS = new Set(['--python', '--index-url', '-i', '--pip-args', '--backend']);

/**
 * The package a runner invocation installs: `packageFlags`' value when given
 * (`--package`, `--from`, `--spec`), else the first argument that is neither an
 * option nor an option's value. Stops at `--` only to take the next word.
 */
function packageArg(args: string[], valueFlags: Set<string>, packageFlags: Set<string>): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (packageFlags.has(arg)) return args[i + 1];
    const inline = /^(--?[\w-]+)=(.+)$/.exec(arg);
    if (inline && packageFlags.has(inline[1])) return inline[2];
    if (arg === '--') return args[i + 1];
    if (valueFlags.has(arg)) { i++; continue; }
    if (arg.startsWith('-')) continue;
    return arg;
  }
  return undefined;
}

/** Drop the leading subcommand words (`dlx`, `exec`, `tool run`); undefined if they don't match. */
function afterSubcommand(args: string[], words: string[][]): string[] | undefined {
  for (const seq of words) {
    const at = args.findIndex(a => !a.startsWith('-'));
    if (at >= 0 && seq.every((w, k) => args[at + k] === w)) return [...args.slice(0, at), ...args.slice(at + seq.length)];
  }
  return undefined;
}

/** What `command args…` installs, if it is a package runner. */
export function runnerPackage(command: unknown, rawArgs: unknown): RunnerPackage | undefined {
  if (typeof command !== 'string' || !command) return undefined;
  const args = Array.isArray(rawArgs) ? rawArgs.filter((a): a is string => typeof a === 'string') : [];
  const cmd = commandName(command);
  let runner = cmd;
  let ecosystem: RunnerPackage['ecosystem'];
  let spec: string | undefined;

  switch (cmd) {
    case 'npx': case 'bunx': case 'pnpx':
      ecosystem = 'npm';
      spec = packageArg(args, NPX_VALUE_FLAGS, new Set(['-p', '--package']));
      break;
    case 'pnpm': case 'yarn': {
      const rest = afterSubcommand(args, [['dlx']]);
      if (!rest) return undefined;
      runner = `${cmd} dlx`;
      ecosystem = 'npm';
      spec = packageArg(rest, NPX_VALUE_FLAGS, new Set(['-p', '--package']));
      break;
    }
    case 'npm': {
      const rest = afterSubcommand(args, [['exec'], ['x']]);
      if (!rest) return undefined;
      runner = 'npm exec';
      ecosystem = 'npm';
      spec = packageArg(rest, NPX_VALUE_FLAGS, new Set(['-p', '--package']));
      break;
    }
    case 'uvx':
      ecosystem = 'pypi';
      spec = packageArg(args, UV_VALUE_FLAGS, new Set(['--from']));
      break;
    case 'uv': {
      const rest = afterSubcommand(args, [['tool', 'run'], ['tool', 'uvx']]);
      if (!rest) return undefined; // `uv run server.py` runs a local script
      runner = 'uv tool run';
      ecosystem = 'pypi';
      spec = packageArg(rest, UV_VALUE_FLAGS, new Set(['--from']));
      break;
    }
    case 'pipx': {
      const rest = afterSubcommand(args, [['run']]);
      if (!rest) return undefined;
      runner = 'pipx run';
      ecosystem = 'pypi';
      spec = packageArg(rest, PIPX_VALUE_FLAGS, new Set(['--spec']));
      break;
    }
    default:
      return undefined;
  }
  if (!spec) return undefined;
  const { name, pin } = ecosystem === 'npm' ? classifyNpm(spec) : classifyPypi(spec);
  return { runner, ecosystem, spec, name, pin };
}

const EXACT_SEMVER = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const COMMIT = /#[0-9a-f]{7,40}$/i;

function isLocal(spec: string): boolean {
  return /^(?:\.{1,2}[\\/]|[\\/]|~[\\/]|file:|[A-Za-z]:[\\/])/.test(spec);
}

function isUrl(spec: string): boolean {
  return /^(?:git\+|git:|https?:|github:|gitlab:|bitbucket:)/.test(spec) || /^[\w.-]+\/[\w.-]+(?:#.*)?$/.test(spec);
}

export function classifyNpm(spec: string): { name: string; pin: PinKind } {
  if (isLocal(spec)) return { name: spec, pin: 'local' };
  // npm:alias@x, git URLs, tarballs: pinned only by a commit or a sha
  if (isUrl(spec) && !spec.startsWith('@')) {
    return { name: spec.replace(/#.*$/, ''), pin: COMMIT.test(spec) || /@sha256:/.test(spec) ? 'exact' : 'none' };
  }
  const at = spec.indexOf('@', spec.startsWith('@') ? 1 : 0);
  if (at < 0) return { name: spec, pin: 'none' };
  const name = spec.slice(0, at);
  const version = spec.slice(at + 1);
  if (!version) return { name, pin: 'none' };
  if (EXACT_SEMVER.test(version) || /^sha\d+[-:]/.test(version)) return { name, pin: 'exact' };
  if (/^[\^~<>=*xX]|\s|\|\||^\d+(?:\.(?:\d+|[xX*]))?$|\.[xX*]/.test(version)) return { name, pin: 'range' };
  return { name, pin: 'tag' };
}

export function classifyPypi(spec: string): { name: string; pin: PinKind } {
  if (isLocal(spec)) return { name: spec, pin: 'local' };
  // name @ git+https://…@<sha> (PEP 508 direct reference)
  const direct = /^([A-Za-z0-9][\w.-]*)(?:\[[^\]]*\])?\s*@\s*(\S+)$/.exec(spec);
  if (direct && /:\/\//.test(direct[2])) {
    return { name: direct[1], pin: /@[0-9a-f]{7,40}$/i.test(direct[2]) || /#sha256=/.test(direct[2]) ? 'exact' : 'none' };
  }
  const m = /^([A-Za-z0-9][\w.-]*)(?:\[[^\]]*\])?\s*(.*)$/.exec(spec.trim());
  if (!m) return { name: spec, pin: 'none' };
  const [, name, rest] = m;
  if (!rest) return { name, pin: 'none' };
  // uv accepts `pkg@1.2.3` (and `@latest`) for tools
  if (rest.startsWith('@')) {
    const v = rest.slice(1);
    return { name, pin: /^\d+(?:\.\d+)*(?:[a-z]+\d*)?$/i.test(v) ? 'exact' : 'tag' };
  }
  if (/^===?\s*[^,*;]+$/.test(rest) && !rest.includes('*')) return { name, pin: 'exact' };
  return { name, pin: 'range' };
}

/** Whether a runner package is pinned (exact) or local — i.e. nothing for an "unpinned" check to report. */
export function isPinnedOrLocal(p: RunnerPackage): boolean {
  return p.pin === 'exact' || p.pin === 'local';
}

/** Short reason text for evidence. */
export function pinProblem(p: RunnerPackage): string {
  switch (p.pin) {
    case 'range': return `"${p.spec}" via ${p.runner} is a version range, not a pin`;
    case 'tag': return `"${p.spec}" via ${p.runner} follows a moving tag`;
    default: return `"${p.spec}" via ${p.runner} has no version pin`;
  }
}
