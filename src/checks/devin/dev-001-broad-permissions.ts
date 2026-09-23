import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

// Commands whose unrestricted Exec() allowance hands the agent arbitrary
// code execution or network egress.
const DANGEROUS_COMMANDS = new Set([
  'curl', 'wget', 'bash', 'sh', 'zsh', 'perl', 'python', 'node',
  'npx', 'ssh', 'sudo', 'chmod', 'rm',
]);

const WILDCARD_RESOURCES = new Set(['*', '**']);

interface ParsedRule {
  action: string;
  resource?: string;
}

/** Parse Devin's `Action(resource)` permission syntax; bare `Action` allowed. */
function parseRule(entry: string): ParsedRule | undefined {
  const m = /^([A-Za-z_]+)\s*(?:\((.*)\))?$/.exec(entry.trim());
  if (!m) return undefined;
  return { action: m[1], resource: m[2]?.trim() };
}

/** First token of an Exec resource, path-stripped: `Exec(/bin/bash -c)` → `bash`. */
function execCommandName(resource: string): string {
  const first = resource.split(/\s+/)[0] ?? '';
  return first.split('/').pop() ?? first;
}

export const dev001 = defineCheck({
  id: 'DEV-001',
  name: 'Devin Over-Broad Permission Rules',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect Devin permission allow rules granting unrestricted execution (Exec(*), Write(**), shell/network commands) or an allow list with no deny guardrails',
  supportedAgents: ['devin'],

  async run(ctx, h) {
    const criticalEvidence: Evidence[] = [];
    const warningEvidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const permissions = config.data.permissions as Record<string, unknown> | undefined;
      if (!permissions || typeof permissions !== 'object') continue;

      const allow = Array.isArray(permissions.allow)
        ? (permissions.allow as unknown[]).filter((e): e is string => typeof e === 'string')
        : [];
      const deny = Array.isArray(permissions.deny)
        ? (permissions.deny as unknown[]).filter((e): e is string => typeof e === 'string')
        : [];

      for (const entry of allow) {
        const rule = parseRule(entry);
        if (!rule) continue;

        if (rule.action === 'Exec' && (rule.resource === undefined || rule.resource === '' || WILDCARD_RESOURCES.has(rule.resource))) {
          criticalEvidence.push({
            file: config.filePath,
            snippet: `permissions.allow: "${entry}"`,
            detail: 'Unrestricted Exec wildcard — the agent may run any command without approval',
          });
          continue;
        }

        if (rule.action === 'Write' && rule.resource !== undefined && WILDCARD_RESOURCES.has(rule.resource)) {
          criticalEvidence.push({
            file: config.filePath,
            snippet: `permissions.allow: "${entry}"`,
            detail: 'Unrestricted Write wildcard — the agent may modify any file without approval',
          });
          continue;
        }

        if (rule.action === 'Exec' && rule.resource) {
          const cmd = execCommandName(rule.resource);
          if (DANGEROUS_COMMANDS.has(cmd)) {
            criticalEvidence.push({
              file: config.filePath,
              snippet: `permissions.allow: "${entry}"`,
              detail: `Allow rule for dangerous command "${cmd}" — grants shell execution, network egress, or privilege escalation without approval`,
            });
          }
        }
      }

      if (allow.length > 0 && deny.length === 0) {
        warningEvidence.push({
          file: config.filePath,
          snippet: `permissions.allow has ${allow.length} rule(s), deny is empty`,
          detail: 'Allow list present with no deny rules — nothing is explicitly blocked as a guardrail',
        });
      }
    }

    const evidence = [...criticalEvidence, ...warningEvidence];
    return h.fromEvidence(evidence, {
      passed: 'No over-broad Devin permission rules detected',
      failed: (n) => `Found ${n} over-broad Devin permission finding(s)`,
      // Deny-gap alone is a hygiene warning, not a critical exposure
      severity: criticalEvidence.length === 0 ? 'warning' : undefined,
      fixDescription: 'Scope Exec()/Write() allow rules to specific commands and paths, and add deny rules for shells, network tools, and credential paths',
    });
  },
});
