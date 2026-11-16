import type { Evidence, FixResult } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { accountBlocks, asPermission, effectivePermission, settingsConfig, noSettingsReason } from './shared.js';
import { configFixTargets } from '../../remediation/fix-refusal.js';

export const gb001 = defineCheck({
  id: 'GB-001',
  name: 'Grok Bot Local Execution Always Allowed',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect Grok Bot "Execution on Local Computer" set to Always allow (localToolPermission: "always" with no stricter admin ceiling) — the cloud agent runs shell commands, reads and writes files under $HOME and reads other AI tools\' MCP setup and prompt history on this computer without asking, outside any sandbox',
  supportedAgents: ['grok-bot'],

  fixTargets: configFixTargets,

  async run(ctx, h) {
    const config = settingsConfig(ctx);
    if (!config) return h.passed(`${noSettingsReason(ctx)} — local execution defaults to "ask"`);

    const critical: Evidence[] = [];
    const warning: Evidence[] = [];
    const info: Evidence[] = [];
    for (const block of accountBlocks(config)) {
      const choice = block.data.localToolPermission;
      const ceiling = block.data.localToolPermissionCeiling;
      if (asPermission(choice) !== 'always') continue;
      if (effectivePermission(choice, ceiling) === 'always') {
        // The exec daemon applies the active account's setting to every
        // connected account; a parked account's takes over once switched to
        const active = block.segments.length === 0;
        (active ? critical : warning).push({
          file: config.filePath,
          snippet: `${block.path}localToolPermission: "always"${ceiling === undefined ? '' : `, localToolPermissionCeiling: "${String(ceiling)}"`}`,
          detail: active
            ? `${block.label}: the cloud agent runs commands and reads/writes files on this computer without approval — unsandboxed, rooted at $HOME`
            : `${block.label}: takes effect when you switch to this account — then the cloud agent runs commands here without approval`,
        });
      } else {
        info.push({
          file: config.filePath,
          snippet: `${block.path}localToolPermission: "always", localToolPermissionCeiling: "${String(ceiling)}"`,
          detail: `${block.label}: capped by the admin ceiling — becomes Always allow if the team policy is lifted`,
          mitigated: true,
        });
      }
    }

    // Other machines on the account: mirrored here, enforced on those machines
    const byMachine = config.data.localToolPermissionByMachineId;
    if (byMachine && typeof byMachine === 'object' && !Array.isArray(byMachine)) {
      const always = Object.entries(byMachine).filter(([, v]) => v === 'always').map(([id]) => id);
      if (always.length > 0) {
        info.push({
          file: config.filePath,
          snippet: `localToolPermissionByMachineId: ${always.length} machine(s) "always"`,
          detail: 'Another computer on this account lets the cloud agent run commands without approval — review it in Settings → Computer → Computers',
          mitigated: true,
        });
      }
    }

    return h.fromEvidence([...critical, ...warning, ...info], {
      passed: 'Grok Bot asks before running anything on this computer',
      failed: (n) => `Found ${n} Grok Bot local-execution setting(s) that skip approval`,
      severity: critical.length > 0 ? undefined : warning.length > 0 ? 'warning' : 'info',
      fixable: critical.length + warning.length > 0,
      fixDescription: 'In Grok Bot set Settings → General → Bot → Execution on Local Computer to "Ask every time" (or "Never allow"); vaso fix writes localToolPermission: "ask" — quit Grok Bot first, since the running app rewrites settings.json',
    });
  },

  async fix(ctx): Promise<FixResult> {
    const config = settingsConfig(ctx);
    const targets = config
      ? accountBlocks(config).filter(b => effectivePermission(b.data.localToolPermission, b.data.localToolPermissionCeiling) === 'always')
      : [];
    if (!config || targets.length === 0) {
      return { checkId: 'GB-001', applied: false, message: 'No Grok Bot account allows local execution without approval' };
    }
    let applied = 0;
    for (const block of targets) {
      const r = await fixFirstConfig([config], {
        checkId: 'GB-001',
        path: [...block.segments, 'localToolPermission'],
        value: 'ask',
        message: 'Set localToolPermission to "ask"',
      });
      if (r.applied) applied++;
    }
    return applied > 0
      ? { checkId: 'GB-001', applied: true, message: `Set localToolPermission to "ask"${applied > 1 ? ` (${applied} accounts)` : ''}` }
      : { checkId: 'GB-001', applied: false, message: 'localToolPermission is already "ask"' };
  },
});
