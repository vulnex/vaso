import { dirname, join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { memorySecretSeverity, scanMemorySecrets } from '../../analyzers/memory-secrets.js';

// Always-on rules files Devin loads from a workspace root or the global
// config dir (CLAUDE.md is covered by the Claude Code checks).
const RULE_FILES = ['AGENTS.md', 'AGENTS.local.md', 'AGENT.md', '.windsurfrules'];

async function listMarkdown(ctx: ScanContext, dir: string): Promise<string[]> {
  try {
    const names = await ctx.fs.readdir(dir);
    return Array.isArray(names) ? names.filter(n => n.endsWith('.md')).map(n => join(dir, n)) : [];
  } catch {
    return [];
  }
}

/** `.devin/global_rules.md` + `.devin/rules/*.md` under `base`. */
async function devinDirRules(ctx: ScanContext, devinDir: string): Promise<string[]> {
  return [join(devinDir, 'global_rules.md'), ...(await listMarkdown(ctx, join(devinDir, 'rules')))];
}

/**
 * Rules files Devin injects into every session for this installation:
 * - project install (installDir = <root>/.devin): root-level rule files plus
 *   .devin/global_rules.md and .devin/rules/*.md
 * - user install (installDir = ~/.config/devin): rule files in the global
 *   config dir plus ~/.devin/global_rules.md and ~/.devin/rules/*.md
 */
async function ruleFileCandidates(ctx: ScanContext): Promise<string[]> {
  const installDir = ctx.installation.installDir;
  if (ctx.installation.profile === 'project') {
    const root = dirname(installDir);
    return [...RULE_FILES.map(f => join(root, f)), ...(await devinDirRules(ctx, installDir))];
  }
  const home = /^(.*)[\\/]\.config[\\/]devin$/.exec(installDir)?.[1] ?? ctx.fs.homedir();
  return [...RULE_FILES.map(f => join(installDir, f)), ...(await devinDirRules(ctx, join(home, '.devin')))];
}

function scanContent(file: string, content: string, evidence: Evidence[]): void {
  evidence.push(...scanMemorySecrets(file, content, 'rules file'));
}

export const dev007 = defineCheck({
  id: 'DEV-007',
  name: 'Devin Rules File Secret Leak',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Scan Devin always-on rules files (AGENTS.md, AGENTS.local.md, AGENT.md, .windsurfrules, .devin/global_rules.md, .devin/rules/*.md) for plaintext secrets and high-entropy strings',
  supportedAgents: ['devin'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let scanned = 0;

    for (const file of await ruleFileCandidates(ctx)) {
      if (!(await ctx.fs.access(file))) continue;
      let content: string;
      try {
        content = await ctx.fs.readFile(file);
      } catch {
        continue;
      }
      if (typeof content !== 'string') continue;
      scanned++;
      scanContent(file, content, evidence);
    }

    if (scanned === 0) {
      return h.passed('No Devin rules files present');
    }

    return h.fromEvidence(evidence, {
      severity: memorySecretSeverity(evidence),
      passed: `No secrets detected in ${scanned} Devin rules file(s)`,
      failed: (n) => `Found ${n} potential secret(s) in Devin rules files`,
      fixDescription: 'Remove the secret from the rules file and rotate the credential — rules files are injected into every session prompt',
    });
  },
});
