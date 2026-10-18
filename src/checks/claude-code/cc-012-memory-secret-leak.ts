import { dirname, extname, join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { memorySecretSeverity, scanMemorySecrets } from '../../analyzers/memory-secrets.js';

async function ruleFiles(dir: string, fs: ScanContext['fs']): Promise<string[]> {
  try {
    const entries = await fs.readdirEntries(dir, { recursive: true });
    return entries
      .filter(e => e.isFile && extname(e.name).toLowerCase() === '.md')
      .map(e => (e.parentPath ? join(e.parentPath, e.name) : join(dir, e.name)));
  } catch {
    return [];
  }
}

export const cc012 = defineCheck({
  id: 'CC-012',
  name: 'Memory File Secret Leak',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Scan ~/.claude/CLAUDE.md, rules/*.md and project CLAUDE.md for plaintext secrets and high-entropy strings',
  supportedAgents: ['claude-code'],

  async run(ctx, h) {
    // User install: ~/.claude/CLAUDE.md. Project install (installDir =
    // <repo>/.claude): Claude Code also loads <repo>/CLAUDE.md and the
    // uncommitted <repo>/CLAUDE.local.md. Both scopes load every
    // <installDir>/rules/**/*.md as memory too.
    const memoryFiles = [join(ctx.installation.installDir, 'CLAUDE.md')];
    if (ctx.installation.profile === 'project') {
      const repo = dirname(ctx.installation.installDir);
      memoryFiles.push(join(repo, 'CLAUDE.md'), join(repo, 'CLAUDE.local.md'));
    }
    memoryFiles.push(...await ruleFiles(join(ctx.installation.installDir, 'rules'), ctx.fs));

    const evidence: Evidence[] = [];
    let found = 0;
    for (const memoryFile of memoryFiles) {
      if (!(await ctx.fs.access(memoryFile))) continue;
      let content: string;
      try {
        content = await ctx.fs.readFile(memoryFile);
      } catch {
        continue;
      }
      found++;
      evidence.push(...scanMemorySecrets(memoryFile, content));
    }
    if (found === 0) return h.passed('No CLAUDE.md memory file present');

    return h.fromEvidence(evidence, {
      severity: memorySecretSeverity(evidence),
      passed: 'No secrets detected in CLAUDE.md memory file',
      failed: (n) => `Found ${n} potential secret(s) in CLAUDE.md`,
      fixDescription: 'Remove the secret from CLAUDE.md and rotate the credential — memory files are often committed to git',
    });
  },
});
