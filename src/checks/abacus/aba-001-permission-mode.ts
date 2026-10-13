import type { Evidence, ParsedConfig } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { fixEveryConfig } from '../../remediation/config-writer.js';
import { isProjectInstall, markUntrustedProject, settingsConfigs } from './shared.js';

// The CLI normalizes the value (trim, lowercase, `_`/space → `-`) and accepts
// aliases: unsupervised = yolo = bypasspermissions (every tool call runs
// unprompted); auto lets the model decide which calls need approval.
const UNSUPERVISED = new Set(['unsupervised', 'yolo', 'bypasspermissions', 'bypass-permissions']);
const AUTO = new Set(['auto']);

function normalize(mode: string): string {
  return mode.trim().toLowerCase().replace(/[\s_]+/g, '-');
}

function classify(mode: unknown): 'critical' | 'warning' | undefined {
  if (typeof mode !== 'string') return undefined;
  const m = normalize(mode);
  if (UNSUPERVISED.has(m) || UNSUPERVISED.has(m.replace(/-/g, ''))) return 'critical';
  if (AUTO.has(m)) return 'warning';
  return undefined;
}

function unsafeModeConfigs(configs: ParsedConfig[]): ParsedConfig[] {
  return settingsConfigs(configs).filter(c => classify(c.data.permissionMode) !== undefined);
}

export const aba001 = defineCheck({
  id: 'ABA-001',
  name: 'Abacus.AI Unsupervised Permission Mode',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect Abacus.AI sessions starting in "unsupervised" mode (alias yolo / bypassPermissions — every tool call runs without approval) or "auto" (the model decides which calls need approval), via permissionMode in config.json / desktop agent-config files or ABACUS_PERMISSION_MODE',
  supportedAgents: ['abacus'],

  async run(ctx, h) {
    const critical: Evidence[] = [];
    const warning: Evidence[] = [];

    for (const config of settingsConfigs(ctx.configs)) {
      const mode = config.data.permissionMode;
      const level = classify(mode);
      if (!level) continue;
      (level === 'critical' ? critical : warning).push({
        file: config.filePath,
        snippet: `permissionMode: "${String(mode)}"`,
        detail: level === 'critical'
          ? 'Sessions start unsupervised — shell commands, edits and MCP tools run without any approval prompt'
          : 'Sessions start in auto mode — the model itself decides which tool calls skip approval',
      });
    }
    await markUntrustedProject(ctx, critical);
    await markUntrustedProject(ctx, warning);

    // The environment override applies to every session the user starts
    if (!isProjectInstall(ctx)) {
      const envMode = ctx.fs.getEnv('ABACUS_PERMISSION_MODE');
      const level = classify(envMode);
      if (level) {
        (level === 'critical' ? critical : warning).push({
          file: '<process env>',
          snippet: `ABACUS_PERMISSION_MODE=${String(envMode)}`,
          detail: 'Environment override sets the starting permission mode for every Abacus.AI session',
        });
      }
    }

    const live = critical.filter(e => !e.mitigated);
    return h.fromEvidence([...critical, ...warning], {
      passed: 'Abacus.AI sessions start in a supervised permission mode',
      failed: (n) => `Found ${n} unsafe Abacus.AI permission mode setting(s)`,
      severity: live.length > 0 ? undefined : (warning.some(e => !e.mitigated) ? 'warning' : undefined),
      fixable: unsafeModeConfigs(ctx.configs).length > 0,
      fixDescription: 'Set permissionMode to "supervise" (or "accept-edits") and unset ABACUS_PERMISSION_MODE; pass --permission-mode per session when needed',
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
