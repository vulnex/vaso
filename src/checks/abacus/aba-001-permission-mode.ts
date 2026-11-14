import type { Evidence, ParsedConfig } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { fixEveryConfig } from '../../remediation/config-writer.js';
import { isProjectInstall, markUntrustedProject, settingsConfigs } from './shared.js';

// The CLI normalizes the value (trim, lowercase, `_`/space → `-`) and accepts
// aliases: unsupervised = yolo = bypasspermissions (every tool call runs
// unprompted). "auto" is the documented default mode (each command and edit is
// checked against the workspace and the request), so setting it explicitly is
// no weaker than leaving it unset and is not reported.
const UNSUPERVISED = new Set(['unsupervised', 'yolo', 'bypasspermissions', 'bypass-permissions']);

function normalize(mode: string): string {
  return mode.trim().toLowerCase().replace(/[\s_]+/g, '-');
}

function unsupervised(mode: unknown): boolean {
  if (typeof mode !== 'string') return false;
  const m = normalize(mode);
  return UNSUPERVISED.has(m) || UNSUPERVISED.has(m.replace(/-/g, ''));
}

function unsafeModeConfigs(configs: ParsedConfig[]): ParsedConfig[] {
  return settingsConfigs(configs).filter(c => unsupervised(c.data.permissionMode));
}

export const aba001 = defineCheck({
  id: 'ABA-001',
  name: 'Abacus.AI Unsupervised Permission Mode',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect Abacus.AI sessions starting in "unsupervised" mode (alias yolo / bypassPermissions — every tool call runs without approval), via permissionMode in config.json / desktop agent-config files or ABACUS_PERMISSION_MODE',
  supportedAgents: ['abacus'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of settingsConfigs(ctx.configs)) {
      const mode = config.data.permissionMode;
      if (!unsupervised(mode)) continue;
      evidence.push({
        file: config.filePath,
        snippet: `permissionMode: "${String(mode)}"`,
        detail: 'Sessions start unsupervised — shell commands, edits and MCP tools run without any approval prompt',
      });
    }
    await markUntrustedProject(ctx, evidence);

    // The environment override applies to every session the user starts
    if (!isProjectInstall(ctx)) {
      const envMode = ctx.fs.getEnv('ABACUS_PERMISSION_MODE');
      if (unsupervised(envMode)) {
        evidence.push({
          file: '<process env>',
          snippet: `ABACUS_PERMISSION_MODE=${String(envMode)}`,
          detail: 'Environment override sets the starting permission mode for every Abacus.AI session',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Abacus.AI sessions do not start unsupervised',
      failed: (n) => `Found ${n} unsupervised Abacus.AI permission mode setting(s)`,
      // Untrusted project files are inactive — nothing to fix until trusted
      fixable: evidence.some(e => !e.mitigated && e.file !== '<process env>'),
      fixDescription: 'Set permissionMode to "supervise" (or keep the default "auto") and unset ABACUS_PERMISSION_MODE; pass --permission-mode per session when needed',
    });
  },

  async fix(ctx) {
    return fixEveryConfig(unsafeModeConfigs(ctx.configs), {
      checkId: 'ABA-001',
      path: 'permissionMode',
      value: 'supervise',
      message: 'Set permissionMode to "supervise"',
      noConfigMessage: 'No config file sets an unsafe permissionMode (an ABACUS_PERMISSION_MODE override must be unset in the shell profile)',
    });
  },
});
