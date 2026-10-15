import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';

const TRUTHY = /^(?:1|true|yes|on)$/i;
// Hermes loads config.yaml with PyYAML (YAML 1.1), where an unquoted
// `mode: off` / `no` / `false` is the boolean False — which Hermes treats as
// "off". VASO's YAML 1.2 parser keeps `off`/`no` as strings and `false` as a
// boolean, so all of them are matched here.
const OFF = /^(?:off|no|n|false)$/i;

/** Surfaces that run without an operator to answer a prompt; "approve"
 *  auto-approves every dangerous command there (default "deny"). */
const UNATTENDED_KEYS = ['cron_mode', 'unattended_mode', 'single_query_mode'];

export const hm008 = defineCheck({
  id: 'HM-008',
  name: 'Hermes Tool-Call Approvals Disabled',
  category: 'hermes',
  severity: 'critical',
  description: 'approvals.mode set to "off" (or a YAML false/no) in cli-config.yaml, approvals.cron_mode / unattended_mode / single_query_mode set to "approve", or HERMES_YOLO_MODE truthy in .env — tool calls (including terminal commands) execute without operator confirmation.',
  supportedAgents: ['hermes'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of ctx.configs) {
      if (config.filePath.endsWith('cli-config.yaml') || config.filePath.endsWith('config.yaml')) {
        const mode = getNestedValue(config.data, 'approvals.mode');
        if (mode === false || (typeof mode === 'string' && OFF.test(mode.trim()))) {
          evidence.push({
            file: config.filePath,
            snippet: `approvals.mode: ${String(mode)}`,
            detail: 'Tool-call approval prompts disabled — every action runs without confirmation',
          });
        }
        for (const key of UNATTENDED_KEYS) {
          const v = getNestedValue(config.data, `approvals.${key}`);
          if (typeof v === 'string' && v.trim().toLowerCase() === 'approve') {
            evidence.push({
              file: config.filePath,
              snippet: `approvals.${key}: ${v}`,
              detail: `Dangerous commands are auto-approved in ${key === 'cron_mode' ? 'cron jobs' : key === 'unattended_mode' ? 'webhook/API sessions' : 'one-shot `hermes chat -q` runs'} — no operator ever confirms them`,
            });
          }
        }
      }
      if (config.format === 'env') {
        const yolo = config.data.HERMES_YOLO_MODE;
        if (typeof yolo === 'string' && TRUTHY.test(yolo.trim())) {
          evidence.push({
            file: config.filePath,
            snippet: `HERMES_YOLO_MODE=${yolo}`,
            detail: 'Persistent YOLO mode bypasses dangerous-command prompts for every Hermes session',
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'Hermes tool-call approvals are enabled',
      failed: (n) => `Found ${n} approval-bypass setting(s) — every tool call runs without confirmation`,
      fixDescription: 'Set approvals.mode: manual (or smart) and cron_mode / unattended_mode / single_query_mode: deny in cli-config.yaml; remove HERMES_YOLO_MODE from .env',
    });
  },
});
