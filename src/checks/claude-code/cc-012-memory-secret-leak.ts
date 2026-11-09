import { dirname, extname, join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { memorySecretSeverity, scanMemorySecrets } from '../../analyzers/memory-secrets.js';
import { claudeProjectScope } from '../../adapters/claude-code.js';
import { pathPresent, readTextIfPresent } from '../../adapters/load-if-present.js';
import { recordListFailure } from '../../core/config-loader.js';

async function ruleFiles(dir: string, fs: ScanContext['fs']): Promise<string[]> {
  try {
    const entries = await fs.readdirEntries(dir, { recursive: true });
    return entries
      .filter(e => e.isFile && extname(e.name).toLowerCase() === '.md')
      .map(e => (e.parentPath ? join(e.parentPath, e.name) : join(dir, e.name)));
  } catch (err) {
    // A rules directory that can't be listed hides every rule in it
    await recordListFailure(dir, fs, err);
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
      // Every CLAUDE.md / CLAUDE.local.md from the working directory up to
      // the repository root loads at launch
      const scope = await claudeProjectScope(dirname(ctx.installation.installDir), ctx.fs);
      memoryFiles.push(...scope.memoryPaths.filter(p => p.endsWith('.md') && !memoryFiles.includes(p)));
    }
    memoryFiles.push(...await ruleFiles(join(ctx.installation.installDir, 'rules'), ctx.fs));

    const evidence: Evidence[] = [];
    let found = 0;
    let unread = 0;
    for (const memoryFile of memoryFiles) {
      if (!(await pathPresent(memoryFile, ctx.fs))) continue;
      // Unreadable: reported as CONFIG-LOAD, not as "no memory file"
      const content = await readTextIfPresent(memoryFile, ctx.fs);
      if (content === undefined) {
        unread++;
        continue;
      }
      found++;
      evidence.push(...scanMemorySecrets(memoryFile, content));
    }
    if (found === 0) {
      return h.passed(unread > 0
        ? `${unread} CLAUDE.md memory file(s) could not be read here — not inspected`
        : 'No CLAUDE.md memory file present');
    }

    return h.fromEvidence(evidence, {
      severity: memorySecretSeverity(evidence),
      passed: 'No secrets detected in CLAUDE.md memory file',
      failed: (n) => `Found ${n} potential secret(s) in CLAUDE.md`,
      fixDescription: 'Remove the secret from CLAUDE.md and rotate the credential — memory files are often committed to git',
    });
  },
});
