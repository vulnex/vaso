import { join, extname } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { scanWithPatterns, SECURITY_PATTERNS } from '../../analyzers/pattern-engine.js';

const PROMPT_INJECTION_RULES = SECURITY_PATTERNS.filter(r => r.category === 'prompt-injection');

async function getAgentDocs(dir: string, fs: ScanContext['fs']): Promise<string[]> {
  const files: string[] = [];
  try {
    const entries = await fs.readdirEntries(dir, { recursive: true });
    for (const entry of entries) {
      if (!entry.isFile) continue;
      if (extname(entry.name).toLowerCase() !== '.md') continue;
      const fullPath = entry.parentPath ? join(entry.parentPath, entry.name) : join(dir, entry.name);
      files.push(fullPath);
    }
  } catch {}
  return files;
}

export const cc011 = defineCheck({
  id: 'CC-011',
  name: 'Sub-Agent Prompt Injection',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Scan ~/.claude/agents/*.md sub-agent definitions for prompt injection patterns',
  supportedAgents: ['claude-code'],

  async run(ctx, h) {
    const agentsDir = join(ctx.installation.installDir, 'agents');
    if (!(await ctx.fs.access(agentsDir))) return h.passed('No sub-agents directory present');

    const evidence: Evidence[] = [];
    const files = await getAgentDocs(agentsDir, ctx.fs);

    for (const file of files) {
      try {
        const content = await ctx.fs.readFile(file);
        const matches = scanWithPatterns(content, PROMPT_INJECTION_RULES);
        for (const m of matches) {
          evidence.push({
            file,
            line: m.line,
            snippet: m.snippet,
            detail: m.description,
          });
        }
      } catch {}
    }

    return h.fromEvidence(evidence, {
      passed: 'No prompt injection patterns found in sub-agent definitions',
      failed: (n) => `Found ${n} prompt injection pattern(s) in sub-agent definitions`,
      fixDescription: 'Audit the flagged sub-agent files; remove instructions that override or escape system prompts',
    });
  },
});
