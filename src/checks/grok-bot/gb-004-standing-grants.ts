import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { DATA_FILES } from '../../adapters/grok-bot.js';
import { asPermission, dataFile, settingsConfig } from './shared.js';

interface Grant {
  scope?: unknown;
  action?: unknown;
  accountScope?: unknown;
}

/**
 * local-tool-standing-grants.v1.json: { version: 1, grants: [{ scope: "action"
 * | "subject", action, accountScope, grantedAtMs, recipient?, recipientName? }] }
 * — persistent "Always allow" answers. An "action" grant covers every
 * recipient/app for that action; a "subject" grant one recipient or app. The
 * daemon honours them unless the ceiling is below "always" or the permission
 * is "never". Recipients are contacts: evidence names actions and counts only.
 */
export const gb004 = defineCheck({
  id: 'GB-004',
  name: 'Grok Bot Standing Approvals',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect persistent Grok Bot "Always allow" grants (local-tool-standing-grants.v1.json) — an action-wide grant lets the agent text anyone or drive any app without asking again; per-recipient grants are listed for review',
  supportedAgents: ['grok-bot'],

  async run(ctx, h) {
    const file = dataFile(ctx, DATA_FILES.standingGrants);
    if (!(await ctx.fs.access(file))) return h.passed('No Grok Bot standing approvals');
    let grants: Grant[];
    try {
      const data = JSON.parse(await ctx.fs.readFile(file)) as { grants?: unknown };
      grants = Array.isArray(data.grants) ? data.grants.filter((g): g is Grant => !!g && typeof g === 'object') : [];
    } catch {
      // Remote scans never collect it (recipients are contacts)
      return h.passed('Grok Bot standing approvals present but not readable — content not inspected');
    }
    if (grants.length === 0) return h.passed('No Grok Bot standing approvals');

    // Grants are honoured only when local execution isn't capped or refused
    const settings = settingsConfig(ctx)?.data ?? {};
    const ceiling = asPermission(settings.localToolPermissionCeiling);
    const inactive = settings.localToolPermission === 'never' || (ceiling !== undefined && ceiling !== 'always');

    const evidence: Evidence[] = [];
    const subjects = new Map<string, number>();
    for (const g of grants) {
      const action = typeof g.action === 'string' ? g.action : 'unknown action';
      if (g.scope === 'action') {
        evidence.push({ file, snippet: `scope: "action", action: "${action}"`, detail: `"${action}" is always allowed for every recipient/app`, mitigated: inactive || undefined });
      } else {
        subjects.set(action, (subjects.get(action) ?? 0) + 1);
      }
    }
    const warningCount = evidence.length;
    for (const [action, n] of subjects) {
      evidence.push({ file, snippet: `scope: "subject", action: "${action}" × ${n}`, detail: `"${action}" is always allowed for ${n} specific recipient(s)/app(s)`, mitigated: inactive || undefined });
    }

    return h.fromEvidence(evidence, {
      passed: 'No Grok Bot standing approvals',
      failed: (n) => `Found ${n} Grok Bot standing approval(s)`,
      severity: warningCount > 0 && !inactive ? undefined : 'info',
      fixDescription: 'Revoke standing approvals in Grok Bot (Settings → Agents → Approvals & Execution); delete local-tool-standing-grants.v1.json to clear them all',
    });
  },
});
