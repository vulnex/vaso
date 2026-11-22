import { join } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';
import { queryPermissions } from '../../core/permissions.js';
import { checkoutDir, Findings, groupOnlyNote } from './shared.js';

/**
 * Two skill trees in a NanoClaw v2 checkout:
 *  - container/skills/  mounted into every agent container (agent instructions/code)
 *  - .claude/skills/    operator skills Claude Code runs on the host during
 *                       setup / add-<channel> / update flows
 * A directory other users can write lets them plant a skill that runs with the
 * agent's (or the operator's) authority.
 */
export const nc005 = defineCheck({
  id: 'NC-005',
  name: 'Skills Directory Writable by Others',
  category: 'nanoclaw',
  severity: 'warning',
  description: 'Verify container/skills (mounted into every agent container) and .claude/skills (operator skills run on the host) in the NanoClaw checkout are not writable by other users.',
  supportedAgents: ['nanoclaw'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const checkout = checkoutDir(ctx);
    if (!checkout) return h.passed('No NanoClaw checkout located');

    const dirs = [
      { path: ctx.installation.skillsDir ?? join(checkout, 'container', 'skills'), what: 'agent skills (mounted into every container)' },
      { path: join(checkout, '.claude', 'skills'), what: 'operator skills (run on the host)' },
    ];
    const findings = new Findings();
    for (const { path, what } of dirs) {
      try {
        const p = await queryPermissions(ctx.fs, path);
        if (p === 'unsupported' || !(p.groupWrite || p.worldWrite)) continue;
        findings.add(
          { file: path, detail: `Permissions ${p.octal ?? p.description} — ${what} writable by ${p.worldWrite ? 'any local user' : 'the group'}; skills can be planted${groupOnlyNote(p.worldWrite)}` },
          p.worldWrite ? 'warning' : 'info',
        );
      } catch {
        // absent
      }
    }

    await findings.markUnreachable(ctx.fs);
    return h.fromEvidence(findings.evidence, {
      passed: 'NanoClaw skills directories are not writable by other users',
      failed: (n) => `${n} NanoClaw skills director${n === 1 ? 'y is' : 'ies are'} writable by other users`,
      severity: findings.severity('warning'),
      fixable: false,
      fixDescription: 'chmod go-w <checkout>/container/skills <checkout>/.claude/skills',
    });
  },
});
