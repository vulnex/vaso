import { CREDENTIAL_FILE_NAMES, CREDENTIAL_SEARCH_DEPTH } from '../checks/policy/pol-005-plaintext-credentials.js';
import { getAdvisoryDatabase } from '../advisory/database.js';
import type { AgentAdapter } from '../adapters/adapter.js';
import type { ProbeManifest } from './snapshot-types.js';
import { cliInstallGlobs, cliInstallSystemPaths } from '../adapters/cli-installs.js';

const SYSTEM_TOOLS = new Set(['which', 'defaults', 'codesign', 'plutil', 'netstat', 'ss', 'ps', 'crontab', 'launchctl']);

/**
 * Home-relative trees an environment variable relocates, as the adapters
 * resolve them (fs.getEnv on the scanned host). Every manifest path under one
 * also gets a `${VAR}/…` twin, which the probe (≥ 1.2.1) expands from its own
 * environment — so an install moved with PICOCLAW_HOME or XDG_CONFIG_HOME is
 * collected on remote scans too. The `~/…` original stays: an older probe
 * ignores what it can't expand. Longest prefix first.
 */
export const RELOCATABLE_TREES: ReadonlyArray<readonly [prefix: string, relocated: readonly string[]]> = [
  ['~/.ironclaw/reborn/', ['${IRONCLAW_REBORN_HOME}/']],
  // 0.x state root
  ['~/.ironclaw/', ['${IRONCLAW_BASE_DIR}/']],
  // Grok Bot: SAND_DATA_ROOT (or SAND_USER_DATA_DIR/sand-data) moves the data
  // root; SAND_USER_DATA_DIR replaces the Electron user-data dir
  ['~/.grokbot/', ['${SAND_DATA_ROOT}/', '${SAND_USER_DATA_DIR}/sand-data/']],
  ['~/.config/Grok Bot/', ['${SAND_USER_DATA_DIR}/', '${XDG_CONFIG_HOME}/Grok Bot/']],
  ['~/Library/Application Support/Grok Bot/', ['${SAND_USER_DATA_DIR}/']],
  ['~/.local/share/', ['${XDG_DATA_HOME}/']],
  ['~/.local/state/', ['${XDG_STATE_HOME}/']],
  ['~/.config/', ['${XDG_CONFIG_HOME}/']],
  ['~/.picoclaw/', ['${PICOCLAW_HOME}/']],
  ['~/.atomic-agent/', ['${ATOMIC_AGENT_STATE_DIR}/']],
  // ZEROCLAW_DATA_DIR/WORKSPACE: config in the dir itself or, legacy, in <parent>/.zeroclaw
  ['~/.zeroclaw/', ['${ZEROCLAW_CONFIG_DIR}/', '${ZEROCLAW_DATA_DIR}/', '${ZEROCLAW_WORKSPACE}/', '${ZEROCLAW_DATA_DIR}/../.zeroclaw/', '${ZEROCLAW_WORKSPACE}/../.zeroclaw/']],
  ['~/.hermes/', ['${HERMES_HOME}/']],
  // OPENCLAW_HOME replaces the home directory; OPENCLAW_STATE_DIR is the state dir itself
  ['~/.openclaw/', ['${OPENCLAW_HOME}/.openclaw/', '${OPENCLAW_STATE_DIR}/']],
  ['~/.codex/', ['${CODEX_HOME}/']],
  ['~/.claude/', ['${CLAUDE_CONFIG_DIR}/']],
  ['~/.copilot/', ['${COPILOT_HOME}/']],
  // GEMINI_CLI_HOME replaces the home directory the .gemini folder lives in
  ['~/.gemini/', ['${GEMINI_CLI_HOME}/.gemini/']],
  ['~/.qwen/', ['${QWEN_HOME}/']],
  // CURSOR_CONFIG_DIR relocates cli-config.json (Cursor CLI configuration reference)
  ['~/.cursor/', ['${CURSOR_CONFIG_DIR}/']],
];

function withRelocatedTwins(paths: string[]): string[] {
  const out = [...paths];
  for (const p of paths) {
    // The tree root itself too (a listing of `~/.grokbot` has no trailing slash)
    const tree = RELOCATABLE_TREES.find(([prefix]) => p.startsWith(prefix) || `${p}/` === prefix);
    if (!tree) continue;
    for (const relocated of tree[1]) {
      out.push(p.startsWith(tree[0]) ? relocated + p.slice(tree[0].length) : relocated.replace(/\/$/, ''));
    }
  }
  return out;
}

/**
 * For every requested `<dir>/package.json`: `<dir>/package-lock.json` and
 * `<dir>/node_modules/<name>/package.json` for the npm packages advisories
 * name (not the whole tree). Literal `node_modules` segments are collected
 * by the probe (only wildcard-reached vendor dirs are skipped).
 */
function dependencyPaths(paths: string[]): string[] {
  const names = [...new Set(getAdvisoryDatabase().advisories
    .map(a => a.affectedDependency)
    .filter(d => d && (d.ecosystem === 'npm' || d.ecosystem === undefined))
    .map(d => d!.name)
    .filter(n => /^(@[a-z0-9._~-]+\/)?[a-z0-9._~-]+$/i.test(n)))].sort();
  // One brace alternative per npm scope keeps the manifest small:
  // `{a,b}` for unscoped names, `@scope/{x,y}` per scope
  const byScope = new Map<string, string[]>();
  for (const n of names) {
    const [scope, rest] = n.startsWith('@') ? [n.slice(0, n.indexOf('/')), n.slice(n.indexOf('/') + 1)] : ['', n];
    byScope.set(scope, [...(byScope.get(scope) ?? []), rest]);
  }
  const alt = (xs: string[]) => (xs.length === 1 ? xs[0] : `{${xs.join(',')}}`);
  const groups = [...byScope].map(([scope, xs]) => (scope ? `${scope}/${alt(xs)}` : alt(xs)));
  const out: string[] = [];
  for (const p of paths) {
    if (!p.endsWith('/package.json')) continue;
    const dir = p.slice(0, -'/package.json'.length);
    out.push(`${dir}/package-lock.json`);
    for (const group of groups) out.push(`${dir}/node_modules/${group}/package.json`);
  }
  return out;
}

/**
 * POL-005 looks for well-known credential file names (.npmrc, .netrc, …) up
 * to CREDENTIAL_SEARCH_DEPTH levels below an install directory. Record the
 * same names at the same depths under each directory an adapter reads a
 * config or package file from (home-relative ones only) — existence and mode,
 * never content.
 */
function credentialFileGlobs(paths: string[]): string[] {
  const names = `{${CREDENTIAL_FILE_NAMES.join(',')}}`;
  const dirs = new Set<string>();
  for (const p of paths) {
    if (!p.startsWith('~/') || p.includes('**') || p.includes('/node_modules/')) continue;
    const dir = p.slice(0, p.lastIndexOf('/'));
    if (dir.length > 2) dirs.add(dir);
  }
  const out: string[] = [];
  for (const dir of dirs) {
    for (let depth = 0; depth <= CREDENTIAL_SEARCH_DEPTH; depth++) out.push(`${dir}/${'*/'.repeat(depth)}${names}`);
  }
  return out;
}

export function buildProbeManifest(adapters: AgentAdapter[]): ProbeManifest {
  const merged: ProbeManifest = {
    filePaths: [],
    globPatterns: [],
    commands: [],
    directoryListings: [],
    envPrefixes: [],
    systemPaths: [],
    systemDirListings: [],
    metadataGlobPatterns: [],
  };

  for (const adapter of adapters) {
    if (adapter.getProbeManifest) {
      const m = adapter.getProbeManifest();
      merged.filePaths.push(...m.filePaths);
      merged.globPatterns.push(...m.globPatterns);
      merged.commands.push(...m.commands);
      merged.directoryListings.push(...m.directoryListings);
      merged.envPrefixes.push(...m.envPrefixes);
      if (m.systemPaths) merged.systemPaths!.push(...m.systemPaths);
      if (m.systemDirListings) merged.systemDirListings!.push(...m.systemDirListings);
      if (m.metadataGlobPatterns) merged.metadataGlobPatterns!.push(...m.metadataGlobPatterns);
    }
    // Every copy of the agent's CLI (system prefixes, user bin dirs, each nvm
    // Node version) so remote scans inventory old copies too. Existence is all
    // discovery needs — never ship the binaries themselves.
    const cli = adapter.getCLICommand?.();
    if (cli) {
      merged.metadataGlobPatterns!.push(...cliInstallGlobs([cli]), ...cliInstallSystemPaths([cli]));
    }
  }

  // nvm's default alias — tells CLI discovery which Node an interactive shell runs
  merged.filePaths.push('~/.nvm/alias/default');
  merged.globPatterns.push('~/.nvm/alias/lts/*');

  // Add common runtime/network check commands
  merged.commands.push(
    { id: 'netstat-tcp', cmd: 'netstat', args: ['-an', '-p', 'tcp'], timeout: 5000 },
    { id: 'ss-tcp', cmd: 'ss', args: ['-tn'], timeout: 5000 },
    { id: 'ps-ancestry', cmd: 'ps', args: ['-eo', 'pid,ppid,comm'], timeout: 5000 },
    { id: 'crontab-list', cmd: 'crontab', args: ['-l'], timeout: 5000 },
    { id: 'launchctl-list', cmd: 'launchctl', args: ['list'], timeout: 5000 },
  );

  // Add runtime check paths — RUN-001 lists these dirs and reads matching
  // units/plists to see what they execute (systemd on Linux, launchd on macOS)
  merged.directoryListings.push('~/Library/LaunchAgents', '~/.config/systemd/user');
  // RUN-003 lists installed editor extensions; RUN-004 reads the Docker socket's mode
  merged.directoryListings.push('~/.vscode/extensions', '~/.vscode-insiders/extensions', '~/.cursor/extensions');
  merged.systemPaths!.push('/var/run/docker.sock');
  merged.systemDirListings!.push('/Library/LaunchAgents', '/Library/LaunchDaemons', '/etc/systemd/system');
  merged.globPatterns.push(
    '~/Library/LaunchAgents/*.plist',
    '~/.config/systemd/user/*.service*',
    '/Library/LaunchAgents/*.plist',
    '/Library/LaunchDaemons/*.plist',
    '/etc/systemd/system/*.service',
  );

  // MCP host configs that aren't owned by any single adapter
  // (Claude Desktop, Cursor, Windsurf — consumed by `vaso mcp scan`)
  merged.filePaths.push(
    '~/Library/Application Support/Claude/claude_desktop_config.json',
    '~/.config/Claude/claude_desktop_config.json',
    '~/.cursor/mcp.json',
    '~/.codeium/windsurf/mcp_config.json',
    '~/.lyrie/mcp.json',
  );

  // ADV-002 reads, next to an install's package.json, its lockfile and the
  // installed copy of each dependency an advisory names — ship the same
  // files, or a remote scan judges by the declared range alone
  const adapterPaths = [...merged.filePaths, ...merged.globPatterns];
  merged.globPatterns.push(...dependencyPaths(adapterPaths));
  // Credential files are metadata only: their contents are secrets, and a
  // remote scan must not copy them to the scanning machine
  merged.metadataGlobPatterns!.push(...credentialFileGlobs(adapterPaths));

  // Deduplicate (after adding the env-relocated twins)
  merged.filePaths = [...new Set(withRelocatedTwins(merged.filePaths))];
  merged.globPatterns = [...new Set(withRelocatedTwins(merged.globPatterns))];
  merged.directoryListings = [...new Set(withRelocatedTwins(merged.directoryListings))];
  merged.metadataGlobPatterns = withRelocatedTwins(merged.metadataGlobPatterns!);
  merged.envPrefixes = [...new Set(merged.envPrefixes)];
  merged.systemPaths = [...new Set(merged.systemPaths!)];
  merged.systemDirListings = [...new Set(merged.systemDirListings!)];
  // Paths already collected with content need no metadata-only duplicate
  const collected = new Set([...merged.globPatterns, ...merged.filePaths, ...merged.systemPaths!]);
  merged.metadataGlobPatterns = [...new Set(merged.metadataGlobPatterns!)].filter(g => !collected.has(g));

  // Agent CLIs run with a throwaway HOME: several initialize state in the
  // user's home on any invocation (a scan must not modify what it scans).
  // System tools keep the real HOME — some read the user's preferences — and so
  // do agent commands that explicitly opt out (`isolateHome: false`): read-only
  // queries that need the user's registered state, verified side-effect free.
  merged.commands = merged.commands.map(c =>
    SYSTEM_TOOLS.has(c.cmd) || c.isolateHome === false ? c : { ...c, isolateHome: true });

  // Deduplicate commands by id
  const seen = new Set<string>();
  merged.commands = merged.commands.filter(c => {
    if (seen.has(c.id)) return false;
    seen.add(c.id);
    return true;
  });

  return merged;
}
