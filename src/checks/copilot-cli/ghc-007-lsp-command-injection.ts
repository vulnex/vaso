import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { stripJsonc } from '../../core/jsonc.js';

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
  name: 'Copilot CLI LSP Command Injection Risk',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect LSP server commands containing shell metacharacters in user or project LSP config',
  supportedAgents: ['copilot-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    await scanLspConfig(join(ctx.installation.installDir, 'lsp-config.json'), ctx, evidence);
    await scanLspConfig(join(process.cwd(), '.github', 'lsp.json'), ctx, evidence);

    return h.fromEvidence(evidence, {
      passed: 'Copilot CLI LSP server commands have no shell metacharacters',
      failed: (n) => `Found ${n} Copilot CLI LSP server command(s) with shell metacharacters`,
      fixDescription: 'Replace shell-style commands with the binary path + args[] array; never embed pipes/semicolons in command',
    });
  },
});
