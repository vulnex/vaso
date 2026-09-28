import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { asRecord, atomicConfigs, llmProviders } from './shared.js';

// Atomic Agent drives a signed-in Claude Code / Codex CLI as a pure inference
// backend, pinning it tool-less (`--tools "" --strict-mcp-config`) or
// read-only (`-s read-only --ignore-user-config`). `subscriptionCli.extraArgs`
// is appended AFTER those flags, so any of these re-arms the vendor CLI's own
// tools on the user's machine — outside Atomic Agent's approval ladder.
const OVERRIDES: Record<string, RegExp> = {
  claude: /^(?:--tools|--allowed-?tools|--allowedTools|--disallowed-?tools|--mcp-config|--dangerously-skip-permissions|--permission-mode|--add-dir|--settings)(?:=|$)/i,
  codex: /^(?:-s|--sandbox|--full-auto|--dangerously-bypass-approvals-and-sandbox|--yolo|-c|--config|--add-dir|--profile|-p)(?:=|$)/i,
};

export const at009 = defineCheck({
  id: 'AT-009',
  name: 'Atomic Agent Subscription CLI Safety Flags Overridden',
  category: 'atomic-agent',
  severity: 'critical',
  description: 'llm.providers[].subscriptionCli.extraArgs contains a flag that undoes the tool lockdown Atomic Agent applies to the Claude Code or Codex CLI it uses for inference (e.g. --tools, --mcp-config, --dangerously-skip-permissions for claude; -s/--sandbox, --full-auto, -c for codex). extraArgs is appended after the safety flags, so the override wins and the vendor CLI can run its own shell/edit tools without Atomic Agent\'s approvals.',
  supportedAgents: ['atomic-agent'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of atomicConfigs(ctx.configs)) {
      llmProviders(config.data).forEach((p, i) => {
        if (p.kind !== 'subscription-cli') return;
        const sub = asRecord(p.subscriptionCli);
        const cli = typeof sub?.cli === 'string' ? sub.cli : undefined;
        const pattern = cli ? OVERRIDES[cli] : undefined;
        if (!pattern || !Array.isArray(sub?.extraArgs)) return;
        const args = (sub.extraArgs as unknown[]).filter((a): a is string => typeof a === 'string');
        const hits = args.filter(a => pattern.test(a.trim()));
        if (hits.length === 0) return;
        const id = typeof p.id === 'string' ? p.id : `#${i}`;
        evidence.push({
          file: config.filePath,
          snippet: `llm.providers[${id}].subscriptionCli.extraArgs: ${JSON.stringify(args)}`,
          detail: `${hits.join(', ')} override${hits.length === 1 ? 's' : ''} the ${cli} CLI lockdown — the inference backend can act on the machine itself, outside Atomic Agent's approval ladder`,
        });
      });
    }
    return h.fromEvidence(evidence, {
      passed: 'Atomic Agent subscription-CLI providers keep the vendor CLI locked down',
      failed: (n) => `${n} subscription-CLI provider(s) override Atomic Agent's tool lockdown`,
      fixDescription: 'Remove tool, sandbox, permission and MCP flags from subscriptionCli.extraArgs; keep extraArgs to inference-only options such as `--effort`',
    });
  },
});
