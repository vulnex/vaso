import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { stripJsonc } from '../../core/jsonc.js';
import { truncateSnippet } from '../../core/patterns.js';
import { hookItemRisks, hookItems, topTier } from '../../analyzers/hook-commands.js';

const SHELL_METACHARS = /[;&|`$()<>]/;

async function scanLspConfig(filePath: string, ctx: ScanContext, evidence: Evidence[]): Promise<void> {
  if (!(await ctx.fs.access(filePath))) return;
  let parsed: Record<string, unknown>;
  try {
    const raw = await ctx.fs.readFile(filePath);
    parsed = JSON.parse(stripJsonc(raw)) as Record<string, unknown>;
  } catch {
    return;
  }

  const servers = parsed.lspServers as Record<string, unknown> | undefined;
  if (!servers || typeof servers !== 'object') return;

  for (const [name, server] of Object.entries(servers)) {
    if (!server || typeof server !== 'object') continue;
    const command = (server as Record<string, unknown>).command;
    if (typeof command !== 'string') continue;
    if (!SHELL_METACHARS.test(command)) continue;
    evidence.push({
      file: filePath,
      snippet: `lspServers.${name}.command = ${command}`,
      detail: 'Shell metacharacters in LSP command — may be evaluated by a shell, enabling command injection',
    });
  }
}

export const ghc007 = defineCheck({
  id: 'GHC-007',
  name: 'Copilot CLI Unsafe LSP or Hook Commands',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect LSP server commands containing shell metacharacters, and hooks (settings.json, ~/.copilot/hooks/*.json, .github/hooks/*.json) that download and execute code, send credentials or hook input over the network, or re-evaluate input as code',
  supportedAgents: ['copilot-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    // The project install (installDir = the repo) carries .github/lsp.json
    await scanLspConfig(
      ctx.installation.profile === 'project'
        ? join(ctx.installation.installDir, '.github', 'lsp.json')
        : join(ctx.installation.installDir, 'lsp-config.json'),
      ctx, evidence,
    );

    // Hooks run on their own on every matching event, with the event JSON
    // on stdin; repository hook files arrive with the clone
    // (docs.github.com/en/copilot/reference/hooks-reference). Same analyzer
    // as CC-003 / CUR-015 / WS-009.
    let critical = false;
    for (const config of ctx.configs) {
      for (const item of hookItems(config.data.hooks)) {
        const risks = hookItemRisks(item);
        const tier = topTier(risks);
        if (!tier) continue;
        if (tier === 'critical') critical = true;
        evidence.push({
          file: config.filePath,
          snippet: `hooks.${item.event}: ${truncateSnippet(item.url ?? item.scripts[0], 120)}`,
          detail: `${item.url ? 'HTTP hook' : 'Hook command'} ${risks.map(r => r.reason).join('; ')}`,
          ...(tier === 'info' ? { mitigated: true } : {}),
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Copilot CLI LSP server commands have no shell metacharacters and no hook downloads code or sends data out',
      failed: (n) => `Found ${n} unsafe Copilot CLI LSP server or hook command(s)`,
      severity: critical ? 'critical' : 'warning',
      fixDescription: 'Replace shell-style LSP commands with the binary path + args[] array; remove hooks you did not add yourself (a repository .github/hooks/*.json arrives with the clone), run reviewed scripts instead of downloads, and send audit data only to https endpoints you control',
    });
  },
});
