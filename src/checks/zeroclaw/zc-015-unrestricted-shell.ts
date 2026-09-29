import { defineCheck } from '../../core/check-builder.js';
import type { Evidence } from '../../core/types.js';
import { asStringArray, effectiveProfiles, isFalse, mainConfig, profileLabel } from './zc-config.js';

/** Tools that execute commands or modify files. `browser` is owned by ZC-011. */
const HIGH_RISK_TOOLS = ['shell', 'file_write', 'file_edit'];

export const zc015 = defineCheck({
  id: 'ZC-015',
  name: 'Unrestricted Shell or Auto-Approved Write Tools',
  category: 'zeroclaw',
  severity: 'warning',
  description:
    'Detect risk profiles whose shell allowlist admits every command including high-risk ones (allowed_commands = ["*"] with block_high_risk_commands=false), or that auto-approve shell/file-write tools; critical when unrestricted commands also run without approval',
  supportedAgents: ['zeroclaw'],

  async run(ctx, h) {
    const config = mainConfig(ctx.configs);
    if (!config) return h.passed('No ZeroClaw config.toml found');
    const evidence: Evidence[] = [];
    let critical = false;

    for (const p of effectiveProfiles(config.data)) {
      const level = typeof p.profile.level === 'string' ? p.profile.level.trim().toLowerCase() : 'supervised';
      if (level === 'readonly') continue;
      const alwaysAsk = asStringArray(p.profile.always_ask).map(s => s.trim());
      if (alwaysAsk.includes('*')) continue;

      const commands = asStringArray(p.profile.allowed_commands).map(s => s.trim());
      const anyCommand = commands.includes('*') && isFalse(p.profile.block_high_risk_commands);

      const auto = asStringArray(p.profile.auto_approve).map(s => s.trim());
      const autoRisky = auto.includes('*')
        ? ['* (every tool)']
        : HIGH_RISK_TOOLS.filter(t => auto.includes(t) && !alwaysAsk.includes(t));
      const shellUnprompted =
        level === 'full' ? !alwaysAsk.includes('shell') : auto.includes('*') || autoRisky.includes('shell');

      if (anyCommand) {
        evidence.push({
          file: config.filePath,
          detail:
            `${profileLabel(p)}: allowed_commands = ["*"] with block_high_risk_commands = false — any command, including high-risk ones, may run` +
            (shellUnprompted ? ' without approval' : ''),
        });
        if (shellUnprompted) critical = true;
      }
      // level = "full" auto-approves everything; ZC-005 reports that.
      if (level !== 'full' && autoRisky.length > 0) {
        evidence.push({
          file: config.filePath,
          detail: `${profileLabel(p)}: auto_approve includes ${autoRisky.join(', ')} — these calls skip the approval prompt`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Shell execution is allowlisted and write tools require approval',
      failed: (n) => `${n} risk-profile setting(s) allow unrestricted or unapproved command execution`,
      severity: critical ? 'critical' : undefined,
      fixDescription:
        'Keep block_high_risk_commands = true (or list explicit allowed_commands) and remove shell / file_write / file_edit / "*" from auto_approve',
    });
  },
});
