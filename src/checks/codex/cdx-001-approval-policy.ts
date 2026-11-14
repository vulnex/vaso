import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { codexProfileName } from '../../adapters/codex.js';

const DANGEROUS_POLICIES = new Set(['never', 'none', 'auto']);

/**
 * MCP server / app tool approval (learn.chatgpt.com/docs/extend/mcp):
 * `default_tools_approval_mode` and `tools.<tool>.approval_mode` take
 * auto | prompt | writes | approve. "approve" pre-approves every call; "auto"
 * (the default) still prompts for risk-hinted (destructive) tools, "writes"
 * for every tool not marked read-only, "prompt" for all.
 */
function preApprovedTools(data: Record<string, unknown>): Array<{ snippet: string; detail: string }> {
  const out: Array<{ snippet: string; detail: string }> = [];
  for (const [table, kind] of [['mcp_servers', 'MCP server'], ['apps', 'app']] as const) {
    const entries = data[table];
    if (!entries || typeof entries !== 'object') continue;
    for (const [id, entry] of Object.entries(entries as Record<string, unknown>)) {
      if (!entry || typeof entry !== 'object') continue;
      const e = entry as Record<string, unknown>;
      if (e.enabled === false) continue;
      const mode = e.default_tools_approval_mode;
      if (typeof mode === 'string' && mode.toLowerCase() === 'approve') {
        out.push({
          snippet: `[${table}.${id}] default_tools_approval_mode = "${mode}"`,
          detail: `Every tool of ${kind} "${id}" runs without an approval prompt, including destructive ones and tools it adds later`,
        });
      }
    }
  }
  return out;
}

export const cdx001 = defineCheck({
  id: 'CDX-001',
  name: 'Codex Approval Policy Disabled',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect when Codex approval_policy is set to a value that skips user confirmation, or an MCP server / app pre-approves every tool (default_tools_approval_mode = "approve")',
  supportedAgents: ['codex'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    const toolEvidence: Evidence[] = [];
    for (const config of ctx.configs) {
      // Profile files only apply under `codex -p <name>` — CDX-008's finding
      if (codexProfileName(config.filePath)) continue;
      for (const t of preApprovedTools(config.data)) toolEvidence.push({ file: config.filePath, ...t });
      const policy = config.data.approval_policy ?? config.data.approvalPolicy;
      if (typeof policy === 'string' && DANGEROUS_POLICIES.has(policy.toLowerCase())) {
        // The documented "read-only non-interactive (CI)" preset: never asks,
        // but commands stay inside the read-only sandbox (no writes, no
        // network) — learn.chatgpt.com/docs/agent-approvals-security
        const mode = config.data.sandbox_mode ?? config.data.sandboxMode;
        if (typeof mode === 'string' && mode.toLowerCase() === 'read-only') {
          evidence.push({
            file: config.filePath,
            mitigated: true,
            detail: `approval_policy = "${policy}" with sandbox_mode = "read-only" — commands run unapproved but can't write or reach the network`,
          });
          continue;
        }
        evidence.push({
          file: config.filePath,
          detail: `approval_policy = "${policy}" — Codex will execute commands without user approval`,
        });
      }
    }

    const livePolicy = evidence.some(e => !e.mitigated);
    return h.fromEvidence([...evidence, ...toolEvidence], {
      passed: 'Codex approval policy requires user confirmation',
      failed: () => livePolicy || toolEvidence.length === 0
        ? 'Codex approval policy bypasses user confirmation'
        : 'Codex MCP/app tools run without user confirmation',
      // Pre-approved MCP tools are a narrower bypass than a policy that never asks
      severity: livePolicy ? undefined : toolEvidence.length > 0 ? 'warning' : undefined,
      // "untrusted" and "on-failure" are deprecated upstream; "on-request" (or a
      // granular policy) is the supported prompting mode
      fixDescription: 'Set approval_policy to "on-request" (or a { granular = { … } } policy) in ~/.codex/config.toml, and use default_tools_approval_mode = "writes" or "prompt" instead of "approve" for MCP servers and apps',
    });
  },
});
