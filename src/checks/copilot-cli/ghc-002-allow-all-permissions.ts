import type { Evidence, ParsedConfig } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { buildBroadPaths, isBroadPath } from '../../analyzers/broad-paths.js';
import { commandFamily, INTERPRETER_COMMANDS, SHELL_COMMANDS, WRAPPER_COMMANDS } from '../../analyzers/command-families.js';

// Saved approvals live in ~/.copilot/permissions-config.json under
// locations[<repo root or dir>].tool_approvals. A `commands` approval lists
// command identifiers — the command name, or name plus subcommand for tools
// such as git — and a request is approved when each of its identifiers is
// listed: the stem `bash` approves every `bash …` invocation, `bash -c`
// scripts included. A trailing `:*` (CLI config-dir reference, "Shell command
// matching") also matches X followed by anything. For a shell, privilege
// wrapper or interpreter either form is any command at all — the persisted
// form of `--allow-all-tools` for that repository. `{kind: "write"}` carries
// no path: every file write in that location stops prompting. (Rule matcher
// read from the 1.0.39 bundle; 1.0.85 keeps the same keys in its native
// runtime.)
const ANY_COMMAND_PREFIXES = new Set([...SHELL_COMMANDS, ...WRAPPER_COMMANDS, ...INTERPRETER_COMMANDS]);
/** Approved for good, these fetch from or upload to any host unreviewed. */
const NETWORK_COMMANDS = new Set(['curl', 'wget', 'nc', 'ncat', 'netcat', 'telnet', 'ssh', 'scp', 'aria2c']);

interface Found {
  evidence: Evidence[];
  critical: boolean;
}

function permissionsConfigEvidence(config: ParsedConfig, home: string, platform: string): Found {
  const found: Found = { evidence: [], critical: false };
  const out = found.evidence;
  const locations = config.data.locations;
  if (!locations || typeof locations !== 'object') return found;
  const broadPaths = buildBroadPaths(home, platform);
  for (const [location, entry] of Object.entries(locations as Record<string, unknown>)) {
    if (!entry || typeof entry !== 'object') continue;
    const rec = entry as Record<string, unknown>;
    for (const approval of Array.isArray(rec.tool_approvals) ? rec.tool_approvals : []) {
      if (!approval || typeof approval !== 'object') continue;
      const a = approval as Record<string, unknown>;
      // `{kind: "mcp", serverName, toolName: null}` approves every tool on
      // the server (config-dir reference, tool_approvals)
      if (a.kind === 'mcp' && typeof a.serverName === 'string' && (a.toolName === null || a.toolName === '*')) {
        out.push({
          file: config.filePath,
          snippet: `locations["${location}"].tool_approvals: mcp "${a.serverName}" (all tools)`,
          detail: `Saved approval runs every tool of MCP server "${a.serverName}" in ${location} without prompting — a prompt-injected call reaches all of them`,
        });
        continue;
      }
      if (a.kind === 'write') {
        out.push({
          file: config.filePath,
          snippet: `locations["${location}"].tool_approvals: write`,
          detail: `Saved approval lets the agent create and edit any file in ${location} without prompting`,
        });
        continue;
      }
      if (a.kind !== 'commands' || !Array.isArray(a.commandIdentifiers)) continue;
      for (const id of a.commandIdentifiers) {
        if (typeof id !== 'string') continue;
        const stem = id.replace(/:\*$/, '').trim().toLowerCase();
        // A command plus subcommand ("npm test") is that one command only
        if (stem === '' || /\s/.test(stem)) continue;
        const name = commandFamily(stem.split('/').pop() ?? stem);
        const snippet = `locations["${location}"].tool_approvals: commands "${id}"`;
        if (ANY_COMMAND_PREFIXES.has(name)) {
          found.critical = true;
          out.push({
            file: config.filePath,
            snippet,
            detail: `Saved approval runs any ${stem} command in ${location} without prompting — equivalent to allowing every shell command there`,
          });
        } else if (NETWORK_COMMANDS.has(name)) {
          out.push({
            file: config.filePath,
            snippet,
            detail: `Saved approval runs any ${stem} command in ${location} without prompting — downloads and uploads to any host go unreviewed`,
          });
        }
      }
    }
    for (const dir of Array.isArray(rec.allowed_directories) ? rec.allowed_directories : []) {
      if (typeof dir !== 'string') continue;
      const broad = isBroadPath(dir, broadPaths, home);
      if (!broad) continue;
      found.critical = true;
      out.push({
        file: config.filePath,
        snippet: `locations["${location}"].allowed_directories: "${dir}"`,
        detail: `Saved directory grant ${broad.reason} — tools reach it without a path prompt`,
      });
    }
  }
  return found;
}

export const ghc002 = defineCheck({
  id: 'GHC-002',
  name: 'Copilot CLI Allow-All Permissions',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect persisted allow-all permissions: settings.json defaultPermissionMode "allow-all", saved permissions-config.json approvals for any shell/interpreter command (`bash`, `python3`, `bash:*`) or directory grants over /, $HOME, /tmp, /etc (critical), any curl/wget/ssh command, every tool of an MCP server (toolName null) or every file write in a location (warning), and the legacy allowAllPermissions:true',
  supportedAgents: ['copilot-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const home = ctx.fs.homedir();
    let critical = false;

    // permissions.disableBypassPermissionsMode blocks every allow-all option;
    // a configured mode it blocks falls back to manual approval (config-dir
    // reference, defaultPermissionMode)
    const blockedBy = ctx.configs.find(c => {
      const p = c.data.permissions as Record<string, unknown> | undefined;
      return !!p && typeof p === 'object' && p.disableBypassPermissionsMode !== undefined && p.disableBypassPermissionsMode !== false;
    })?.filePath;

    for (const config of ctx.configs) {
      if (config.filePath.endsWith('permissions-config.json')) {
        const found = permissionsConfigEvidence(config, home, ctx.platform);
        evidence.push(...found.evidence);
        critical ||= found.critical;
        continue;
      }
      if (!config.filePath.endsWith('settings.json')) continue;
      // Repository settings (.github/copilot/settings*.json) carry hooks, not the session's permission mode
      if (ctx.installation.profile === 'project') continue;
      // defaultPermissionMode: "allow-all" starts every interactive session
      // with broad permissions "equivalent to --allow-all" (user settings)
      const mode = config.data.defaultPermissionMode;
      if (typeof mode === 'string' && mode.toLowerCase() === 'allow-all') {
        if (!blockedBy) critical = true;
        evidence.push({
          file: config.filePath,
          snippet: `defaultPermissionMode = "${mode}"`,
          detail: blockedBy
            ? `New sessions would start in allow-all mode, but permissions.disableBypassPermissionsMode in ${blockedBy} blocks it (sessions start in manual approval)`
            : 'New interactive sessions start in allow-all mode — every tool, path and URL runs without prompting (equivalent to --allow-all)',
          ...(blockedBy ? { mitigated: true } : {}),
        });
      }
      // Not in the current settings reference (allow-all is a launch flag,
      // `--allow-all-tools`/`--yolo`), kept for configs written by older builds
      if (config.data.allowAllPermissions === true) {
        critical = true;
        evidence.push({
          file: config.filePath,
          snippet: 'allowAllPermissions = true',
          detail: 'Every tool call (including shell commands) auto-approves without prompting',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Copilot CLI requires per-tool approval',
      failed: (n) => `Found ${n} persisted allow-all permission grant(s) in Copilot CLI config`,
      severity: critical ? 'critical' : 'warning',
      fixDescription: 'Set defaultPermissionMode to "manual" (or "assisted"), remove broad saved approvals from ~/.copilot/permissions-config.json (or run /reset-allowed-tools in that repo), drop allowAllPermissions from settings.json, and consider permissions.disableBypassPermissionsMode: "disable" to block the --allow-all/--yolo flags',
    });
  },
});
