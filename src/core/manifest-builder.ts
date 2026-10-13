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
  ['~/.local/share/', ['${XDG_DATA_HOME}/']],
  ['~/.local/state/', ['${XDG_STATE_HOME}/']],
  ['~/.config/', ['${XDG_CONFIG_HOME}/']],
  ['~/.picoclaw/', ['${PICOCLAW_HOME}/']],
  ['~/.atomic-agent/', ['${ATOMIC_AGENT_STATE_DIR}/']],
  ['~/.zeroclaw/', ['${ZEROCLAW_CONFIG_DIR}/', '${ZEROCLAW_DATA_DIR}/', '${ZEROCLAW_WORKSPACE}/']],
  ['~/.hermes/', ['${HERMES_HOME}/']],
  ['~/.openclaw/', ['${OPENCLAW_HOME}/']],
  ['~/.codex/', ['${CODEX_HOME}/']],
  ['~/.claude/', ['${CLAUDE_CONFIG_DIR}/']],
  ['~/.copilot/', ['${COPILOT_HOME}/']],
  // GEMINI_CLI_HOME replaces the home directory the .gemini folder lives in
  ['~/.gemini/', ['${GEMINI_CLI_HOME}/.gemini/']],
];

function withRelocatedTwins(paths: string[]): string[] {
  const out = [...paths];
  for (const p of paths) {
    const tree = RELOCATABLE_TREES.find(([prefix]) => p.startsWith(prefix));
    if (!tree) continue;
    for (const relocated of tree[1]) out.push(relocated + p.slice(tree[0].length));
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
