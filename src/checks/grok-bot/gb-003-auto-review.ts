import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { accountBlocks, settingsConfig, noSettingsReason } from './shared.js';

function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

function preview(s: string): string {
  const one = s.replace(/\s+/g, ' ').trim();
  return one.length > 80 ? `${one.slice(0, 80)}…` : one;
}

export const gb003 = defineCheck({
  id: 'GB-003',
  name: 'Grok Bot Auto-Review Disabled or Widened',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Grok Bot auto-review turned off (autoReviewInstructions.isEnabled: false) — shell commands, app calls, computer use and agent launches are no longer screened before they run — and custom "Allow automatically" instructions that widen what it lets through',
  supportedAgents: ['grok-bot'],

  async run(ctx, h) {
    const config = settingsConfig(ctx);
    if (!config) return h.passed(`${noSettingsReason(ctx)} — auto-review defaults to on`);

    const warning: Evidence[] = [];
    const info: Evidence[] = [];
    for (const block of accountBlocks(config)) {
      const review = block.data.autoReviewInstructions;
      if (!isRecord(review)) continue;
      if (review.isEnabled === false) {
        warning.push({
          file: config.filePath,
          snippet: `${block.path}autoReviewInstructions.isEnabled: false`,
          detail: `${block.label}: risky actions are no longer reviewed before they run (an admin can enforce it back on)`,
        });
      }
      const allow = Array.isArray(review.allowInstructions)
        ? review.allowInstructions.filter((s): s is string => typeof s === 'string' && s.trim() !== '')
        : [];
      for (const rule of allow) {
        info.push({
          file: config.filePath,
          snippet: `${block.path}autoReviewInstructions.allowInstructions: "${preview(rule)}"`,
          detail: `${block.label}: custom rule auto-allows matching actions — "Ask first" rules still win`,
        });
      }
    }

    return h.fromEvidence([...warning, ...info], {
      passed: 'Grok Bot auto-review is on with default rules',
      failed: (n) => `Found ${n} Grok Bot auto-review setting(s) worth reviewing`,
      severity: warning.length > 0 || info.length === 0 ? undefined : 'info',
      fixDescription: 'Turn auto-review back on in Grok Bot (Settings → Agents → Approvals & Execution) and keep "Allow automatically" rules narrow',
    });
  },
});
