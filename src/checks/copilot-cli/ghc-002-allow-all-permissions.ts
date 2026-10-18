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

function permissionsConfigEvidence(config: ParsedConfig, home: string): Found {
  const found: Found = { evidence: [], critical: false };
  const out = found.evidence;
  const locations = config.data.locations;
  if (!locations || typeof locations !== 'object') return found;
  const broadPaths = buildBroadPaths(home);
  for (const [location, entry] of Object.entries(locations as Record<string, unknown>)) {
    if (!entry || typeof entry !== 'object') continue;
    const rec = entry as Record<string, unknown>;
    for (const approval of Array.isArray(rec.tool_approvals) ? rec.tool_approvals : []) {
      if (!approval || typeof approval !== 'object') continue;
      const a = approval as Record<string, unknown>;
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
  description: 'Detect persisted allow-all permissions: saved permissions-config.json approvals for any shell/interpreter command (`bash`, `python3`, `bash:*`) or directory grants over /, $HOME, /tmp, /etc (critical), any curl/wget/ssh command or every file write in a location (warning), and the legacy allowAllPermissions:true',
  supportedAgents: ['copilot-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const home = ctx.fs.homedir();
    let critical = false;

    for (const config of ctx.configs) {
      if (config.filePath.endsWith('permissions-config.json')) {
        const found = permissionsConfigEvidence(config, home);
        evidence.push(...found.evidence);
        critical ||= found.critical;
        continue;
      }
      if (!config.filePath.endsWith('settings.json')) continue;
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
      fixDescription: 'Remove broad saved approvals from ~/.copilot/permissions-config.json (or run /reset-allowed-tools in that repo), drop allowAllPermissions from settings.json, and consider permissions.disableBypassPermissionsMode: "disable" to block the --allow-all/--yolo flags',
    });
  },
});
