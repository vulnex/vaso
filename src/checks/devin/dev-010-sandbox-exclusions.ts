import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { DANGEROUS_COMMANDS, execCommandName, parseRule } from './dev-001-broad-permissions.js';
import { commandFamily } from '../../analyzers/command-families.js';

const WILDCARD = new Set(['', '*', '**']);

/**
 * `sandbox.excluded.allow` runs matching commands *outside* the OS sandbox
 * with no prompt (Devin sandbox docs). A wildcard defeats the sandbox
 * entirely; excluding a shell, interpreter or downloader lets it run any
 * payload unsandboxed. `sandbox` is user-config only — Devin ignores it in
 * a project's .devin/config[.local].json — so project installs are skipped.
 */
export const dev010 = defineCheck({
  id: 'DEV-010',
  name: 'Devin Over-Broad Sandbox Exclusions',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect sandbox.excluded.allow rules that let every command, or a shell/interpreter/downloader, run outside the Devin OS sandbox without a prompt',
  supportedAgents: ['devin'],

  async run(ctx, h) {
    const critical: Evidence[] = [];
    const warning: Evidence[] = [];
    const userConfigs = ctx.installation.profile === 'project' ? [] : ctx.configs;

    for (const config of userConfigs) {
      const sandbox = config.data.sandbox as Record<string, unknown> | undefined;
      const excluded = sandbox?.excluded as Record<string, unknown> | undefined;
      const allow = Array.isArray(excluded?.allow) ? excluded!.allow as unknown[] : [];

      for (const entry of allow) {
        if (typeof entry !== 'string') continue;
        const rule = parseRule(entry);
        if (!rule || rule.action.toLowerCase() !== 'exec') continue;
        const resource = (rule.resource ?? '').trim();
        if (WILDCARD.has(resource)) {
          critical.push({
            file: config.filePath,
            snippet: `sandbox.excluded.allow: "${entry}"`,
            detail: 'Every command runs outside the sandbox without a prompt — the OS sandbox is effectively disabled',
          });
          continue;
        }
        const cmd = execCommandName(resource);
        if (DANGEROUS_COMMANDS.has(commandFamily(cmd))) {
          warning.push({
            file: config.filePath,
            snippet: `sandbox.excluded.allow: "${entry}"`,
            detail: `"${cmd}" runs outside the sandbox without a prompt — it can execute or fetch arbitrary payloads unsandboxed`,
          });
        }
      }
    }

    return h.fromEvidence([...critical, ...warning], {
      passed: 'No over-broad Devin sandbox exclusions',
      failed: (n) => `Found ${n} over-broad Devin sandbox exclusion(s)`,
      severity: critical.length === 0 ? 'warning' : undefined,
      fixDescription: 'Scope sandbox.excluded.allow to specific subcommands (e.g. "Exec(git status *)"); move broader rules to excluded.ask',
    });
  },
});
