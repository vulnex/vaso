import { dirname, join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { scanMemorySecrets } from '../../analyzers/memory-secrets.js';
import { MemoryReader } from '../../analyzers/memory-read.js';
import { recordListFailure } from '../../core/config-loader.js';

// Always-on rules files Devin loads from a workspace root or the global
// config dir (CLAUDE.md is covered by the Claude Code checks).
const RULE_FILES = ['AGENTS.md', 'AGENTS.local.md', 'AGENT.md', '.windsurfrules'];

/** Whether `path` resolves to a directory (false when it can't be resolved — the reader reports that). */
async function isDirectory(ctx: ScanContext, path: string): Promise<boolean> {
  try {
    return (await ctx.fs.stat(path)).isDirectory();
  } catch {
    return false;
  }
}

async function listMarkdown(ctx: ScanContext, dir: string): Promise<string[]> {
  try {
    // Regular files (or links to them) only: a directory named `x.md` is not
    // a rules file
    const entries = await ctx.fs.readdirEntries(dir);
    if (!Array.isArray(entries)) return [];
    const out: string[] = [];
    for (const e of entries) {
      if (!e.name.endsWith('.md') || e.isDirectory) continue;
      // A link reports itself, not its target: follow it to drop `x.md -> some/dir`
      if (e.isSymbolicLink && await isDirectory(ctx, join(dir, e.name))) continue;
      out.push(join(dir, e.name));
    }
    return out;
  } catch (err) {
    // A rules folder that can't be listed hides its files
    await recordListFailure(dir, ctx.fs, err);
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
  for (const e of scanMemorySecrets(file, content, 'rules file')) evidence.push(e);
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
    const reader = new MemoryReader(ctx.fs);

    for (const file of await ruleFileCandidates(ctx)) {
      // Present but unreadable: reported as CONFIG-LOAD
      const content = await reader.read(file);
      if (typeof content !== 'string') continue;
      scanned++;
      scanContent(file, content, evidence);
    }

    if (scanned === 0 && reader.linked.length === 0) {
      return h.passed(reader.unverified.length > 0 ? reader.notVerified() : 'No Devin rules files present');
    }

    return reader.result(h, evidence, {
      passed: `No secrets detected in ${scanned} Devin rules file(s)${reader.note()}`,
      failed: (n) => `Found ${n} potential secret(s) in Devin rules files`,
      fixDescription: 'Remove the secret from the rules file and rotate the credential — rules files are injected into every session prompt',
    });
  },
});
