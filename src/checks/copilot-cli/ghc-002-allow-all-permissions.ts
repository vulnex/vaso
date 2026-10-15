import type { Evidence, ParsedConfig } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { buildBroadPaths, isBroadPath } from '../../analyzers/broad-paths.js';

// A saved `commands` approval `X:*` matches X followed by anything (CLI
// config-dir reference, "Shell command matching"). For a shell, privilege
// wrapper or interpreter that is any command at all — the persisted form of
// `--allow-all-tools` for that repository.
const ANY_COMMAND_PREFIXES = new Set([
  'bash', 'sh', 'zsh', 'fish', 'dash', 'ksh', 'pwsh', 'powershell', 'cmd',
  'sudo', 'su', 'doas', 'env', 'xargs', 'eval', 'exec',
  'python', 'python3', 'node', 'deno', 'bun', 'perl', 'ruby', 'php', 'osascript',
]);

function permissionsConfigEvidence(config: ParsedConfig, home: string): Evidence[] {
  const out: Evidence[] = [];
  const locations = config.data.locations;
  if (!locations || typeof locations !== 'object') return out;
  const broadPaths = buildBroadPaths(home);
  for (const [location, entry] of Object.entries(locations as Record<string, unknown>)) {
    if (!entry || typeof entry !== 'object') continue;
    const rec = entry as Record<string, unknown>;
    for (const approval of Array.isArray(rec.tool_approvals) ? rec.tool_approvals : []) {
      if (!approval || typeof approval !== 'object') continue;
      const a = approval as Record<string, unknown>;
      if (a.kind !== 'commands' || !Array.isArray(a.commandIdentifiers)) continue;
      for (const id of a.commandIdentifiers) {
        if (typeof id !== 'string' || !id.endsWith(':*')) continue;
        const prefix = id.slice(0, -2).trim().toLowerCase();
        if (!ANY_COMMAND_PREFIXES.has(prefix.split('/').pop() ?? prefix)) continue;
        out.push({
          file: config.filePath,
          snippet: `locations["${location}"].tool_approvals: commands "${id}"`,
          detail: `Saved approval runs any ${prefix} command in ${location} without prompting — equivalent to allowing every shell command there`,
        });
      }
    }
    for (const dir of Array.isArray(rec.allowed_directories) ? rec.allowed_directories : []) {
      if (typeof dir !== 'string') continue;
      const broad = isBroadPath(dir, broadPaths, home);
      if (!broad) continue;
      out.push({
        file: config.filePath,
        snippet: `locations["${location}"].allowed_directories: "${dir}"`,
        detail: `Saved directory grant ${broad.reason} — tools reach it without a path prompt`,
      });
    }
  }
  return out;
}

export const ghc002 = defineCheck({
  id: 'GHC-002',
  name: 'Copilot CLI Allow-All Permissions',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect persisted allow-all permissions: saved permissions-config.json approvals for any shell/interpreter command or over /, $HOME, /tmp, /etc, and the legacy allowAllPermissions:true',
  supportedAgents: ['copilot-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const home = ctx.fs.homedir();

    for (const config of ctx.configs) {
      if (config.filePath.endsWith('permissions-config.json')) {
        evidence.push(...permissionsConfigEvidence(config, home));
        continue;
      }
      if (!config.filePath.endsWith('settings.json')) continue;
      // Not in the current settings reference (allow-all is a launch flag,
      // `--allow-all-tools`/`--yolo`), kept for configs written by older builds
      if (config.data.allowAllPermissions === true) {
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
      fixDescription: 'Remove broad saved approvals from ~/.copilot/permissions-config.json (or run /reset-allowed-tools in that repo), drop allowAllPermissions from settings.json, and consider permissions.disableBypassPermissionsMode: "disable" to block the --allow-all/--yolo flags',
    });
  },
});
