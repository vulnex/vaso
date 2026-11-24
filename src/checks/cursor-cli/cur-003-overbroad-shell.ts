import { basename } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { overbroadShellReason, shellDenied } from './permission-rules.js';

export const cur003 = defineCheck({
  id: 'CUR-003',
  name: 'Cursor Overbroad Shell Allow',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect permissions.allow entries (cli-config.json) and permissions.json terminalAllowlist entries that grant unbounded shell access',
  supportedAgents: ['cursor-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      // permissions.json terminalAllowlist: commands that run without
      // approval, prefix-matched, `command` or `command:args_glob`
      // (cursor.com/docs/reference/permissions)
      if (basename(config.filePath) === 'permissions.json') {
        const list = Array.isArray(config.data.terminalAllowlist) ? config.data.terminalAllowlist : [];
        for (const entry of list) {
          if (typeof entry !== 'string') continue;
          const reason = entry.trim() === '' ? undefined : overbroadShellReason(`Shell(${entry.trim()})`, { foldCase: true });
          if (!reason) continue;
          evidence.push({
            file: config.filePath,
            snippet: `terminalAllowlist: "${entry}"`,
            detail: `Runs without approval: the entry ${reason}`,
          });
        }
        continue;
      }
      const perms = config.data.permissions as Record<string, unknown> | undefined;
      if (!perms || typeof perms !== 'object') continue;
      const allow = Array.isArray(perms.allow) ? (perms.allow as unknown[]).filter((a): a is string => typeof a === 'string') : [];
      const deny = Array.isArray(perms.deny) ? (perms.deny as unknown[]).filter((a): a is string => typeof a === 'string') : [];

      for (const rule of allow) {
        if (shellDenied(rule, deny)) continue; // deny wins
        const reason = overbroadShellReason(rule, { platform: ctx.platform });
        if (!reason) continue;
        evidence.push({
          file: config.filePath,
          snippet: `permissions.allow: "${rule}"`,
          detail: `Auto-approves arbitrary shell commands: the rule ${reason}`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Cursor permissions.allow has no overbroad shell entries',
      failed: (n) => `Found ${n} overbroad Shell allow rule(s) in Cursor config`,
      fixDescription: 'Replace catch-alls with specific commands (e.g. Shell(git), Shell(npm)) and add deny rules for risky shells',
    });
  },
});
