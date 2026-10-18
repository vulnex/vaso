import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { accountBlocks, settingsConfig, noSettingsReason } from './shared.js';

// toolPermissions.scopes["mcp:<serverId>"] = { tools?: { <tool>: P }, reads?: P, writes?: P }
// with P ∈ always_allow | needs_approval | blocked; a tool resolves as
// tools[name] ?? (read-only ? reads : writes) ?? auto-review.
const ALWAYS = 'always_allow';

function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

export const gb002 = defineCheck({
  id: 'GB-002',
  name: 'Grok Bot Connector Tools Auto-Approved',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Grok Bot app/MCP connector permissions set to "always_allow" (toolPermissions in settings.json) — write tools, or every tool of a connector, then run without approval or auto-review',
  supportedAgents: ['grok-bot'],

  async run(ctx, h) {
    const config = settingsConfig(ctx);
    if (!config) return h.passed(noSettingsReason(ctx));

    const warning: Evidence[] = [];
    const info: Evidence[] = [];
    for (const block of accountBlocks(config)) {
      const perms = block.data.toolPermissions;
      const scopes = isRecord(perms) ? perms.scopes : undefined;
      if (!isRecord(scopes)) continue;
      for (const [scope, policy] of Object.entries(scopes)) {
        if (!isRecord(policy)) continue;
        const base = `${block.path}toolPermissions.scopes["${scope}"]`;
        if (policy.writes === ALWAYS) {
          warning.push({ file: config.filePath, snippet: `${base}.writes: "${ALWAYS}"`, detail: `${block.label}: every write tool of ${scope} runs without approval` });
        }
        if (policy.reads === ALWAYS) {
          info.push({ file: config.filePath, snippet: `${base}.reads: "${ALWAYS}"`, detail: `${block.label}: read-only tools of ${scope} run without approval` });
        }
        if (isRecord(policy.tools)) {
          const tools = Object.entries(policy.tools).filter(([, p]) => p === ALWAYS).map(([t]) => t);
          if (tools.length > 0) {
            warning.push({
              file: config.filePath,
              snippet: `${base}.tools: ${tools.slice(0, 5).join(', ')}${tools.length > 5 ? ` (+${tools.length - 5})` : ''} → "${ALWAYS}"`,
              detail: `${block.label}: ${tools.length} ${scope} tool(s) skip approval and auto-review`,
            });
          }
        }
      }
    }

    return h.fromEvidence([...warning, ...info], {
      passed: 'No Grok Bot connector tool skips approval',
      failed: (n) => `Found ${n} Grok Bot connector permission(s) set to always allow`,
      severity: warning.length > 0 || info.length === 0 ? undefined : 'info',
      fixDescription: 'In Grok Bot review Settings → Apps and set write tools back to "Ask first" (needs_approval)',
    });
  },
});
