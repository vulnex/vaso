import { basename } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { overbroadPathRule } from './permission-rules.js';

const OVERBROAD_WEB_RULES = [
  /^WebFetch\s*\(\s*\*\s*\)$/i,
  /^Mcp\s*\(\s*\*\s*(:\s*\*\s*)?\)$/i,
];

export const cur009 = defineCheck({
  id: 'CUR-009',
  name: 'Cursor Overbroad Path/Web Allow',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect permissions.allow entries granting unbounded Write/Read/WebFetch/Mcp access, permissions.json mcpAllowlist "*:*", and sandbox.json additionalReadwritePaths over the home directory, filesystem root or credential stores',
  supportedAgents: ['cursor-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const home = ctx.fs.homedir();

    for (const config of ctx.configs) {
      const name = basename(config.filePath);
      // permissions.json mcpAllowlist `server:tool` (case-insensitive, glob
      // `*` inside names): "*:*" — or "*:**", "**:*" — runs every tool of
      // every MCP server without approval
      if (name === 'permissions.json') {
        for (const entry of Array.isArray(config.data.mcpAllowlist) ? config.data.mcpAllowlist : []) {
          if (typeof entry !== 'string' || !/^\s*\*+\s*:\s*\*+\s*$/.test(entry)) continue;
          evidence.push({
            file: config.filePath,
            snippet: `mcpAllowlist: "${entry}"`,
            detail: 'Every tool of every MCP server runs without approval — a prompt-injected call reaches all of them unchecked',
          });
        }
        continue;
      }
      // sandbox.json additionalReadwritePaths: extra paths sandboxed
      // commands may write. The workspace is writable already; the home
      // directory, / or a credential store / shell startup file is not.
      // They apply only to type "workspace_readwrite" (the default) —
      // cursor.com/docs/reference/sandbox.
      if (name === 'sandbox.json') {
        const type = config.data.type;
        if (typeof type === 'string' && type !== 'workspace_readwrite') continue;
        for (const entry of Array.isArray(config.data.additionalReadwritePaths) ? config.data.additionalReadwritePaths : []) {
          if (typeof entry !== 'string') continue;
          const reason = overbroadPathRule(`Write(${entry})`, home, ctx.platform);
          if (!reason || reason.startsWith('covers every file in the workspace')) continue;
          evidence.push({
            file: config.filePath,
            snippet: `additionalReadwritePaths: "${entry}"`,
            detail: `${reason.startsWith('lets the agent write ') ? `Sandbox write access to ${reason.slice('lets the agent write '.length)}` : `Sandbox-writable path ${reason}`} — sandboxed commands run without a prompt`,
          });
        }
        continue;
      }
      const perms = config.data.permissions as Record<string, unknown> | undefined;
      if (!perms || typeof perms !== 'object') continue;
      const allow = Array.isArray(perms.allow) ? (perms.allow as unknown[]).filter((a): a is string => typeof a === 'string') : [];

      for (const rule of allow) {
        const pathReason = overbroadPathRule(rule, home, ctx.platform);
        if (!pathReason && !OVERBROAD_WEB_RULES.some(p => p.test(rule))) continue;
        evidence.push({
          file: config.filePath,
          snippet: `permissions.allow: "${rule}"`,
          detail: pathReason
            ? `Path rule ${pathReason} — grants far more access than typically intended`
            : 'Wildcard path/web rule grants far more access than typically intended',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Cursor allow rules have no unbounded path or web wildcards',
      failed: (n) => `Found ${n} overbroad path/web allow rule(s) in Cursor config`,
      fixDescription: 'Narrow rules to specific paths/domains (e.g. Write(src/**), WebFetch(*.example.com))',
    });
  },
});
