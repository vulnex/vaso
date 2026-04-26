import { join } from 'node:path';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { findHighEntropyBlocks } from '../../analyzers/entropy.js';

const KNOWN_KEY_PREFIXES: { pattern: RegExp; name: string }[] = [
  { pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}/, name: 'Anthropic API key' },
  { pattern: /\bsk-[A-Za-z0-9]{32,}/, name: 'OpenAI-style API key' },
  { pattern: /\bghp_[A-Za-z0-9]{20,}/, name: 'GitHub personal access token' },
  { pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}/, name: 'GitHub fine-grained PAT' },
  { pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}/, name: 'Slack token' },
  { pattern: /\bAKIA[0-9A-Z]{16}\b/, name: 'AWS access key ID' },
];

const ENTROPY_THRESHOLD = 5.5;
const MIN_BLOCK_LEN = 40;

export const cc012: CheckModule = {
  id: 'CC-012',
  name: 'Memory File Secret Leak',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Scan ~/.claude/CLAUDE.md and project CLAUDE.md for plaintext secrets and high-entropy strings',
  supportedAgents: ['claude-code'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const memoryFile = join(ctx.installation.installDir, 'CLAUDE.md');

    if (!(await ctx.fs.access(memoryFile))) {
      return {
        id: 'CC-012',
        name: 'Memory File Secret Leak',
        category: 'coding-agent',
        severity: 'critical',
        passed: true,
        message: 'No CLAUDE.md memory file present',
      };
    }

    let content: string;
    try {
      content = await ctx.fs.readFile(memoryFile);
    } catch {
      return {
        id: 'CC-012',
        name: 'Memory File Secret Leak',
        category: 'coding-agent',
        severity: 'critical',
        passed: true,
        message: 'CLAUDE.md is not readable',
      };
    }

    // Known prefix matches
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      for (const { pattern, name } of KNOWN_KEY_PREFIXES) {
        const m = pattern.exec(lines[i]);
        if (m) {
          evidence.push({
            file: memoryFile,
            line: i + 1,
            snippet: `${m[0].slice(0, 12)}…`,
            detail: `Plaintext ${name} in memory file`,
          });
        }
      }
    }

    // High-entropy blocks (catch unknown-format secrets)
    const blocks = findHighEntropyBlocks(content, ENTROPY_THRESHOLD, MIN_BLOCK_LEN);
    for (const b of blocks) {
      // De-dup with known-prefix matches on the same line
      if (evidence.some(e => e.line === b.line)) continue;
      evidence.push({
        file: memoryFile,
        line: b.line,
        snippet: b.snippet,
        detail: `High-entropy string (${b.entropy} bits) — possible embedded secret`,
      });
    }

    return {
      id: 'CC-012',
      name: 'Memory File Secret Leak',
      category: 'coding-agent',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No secrets detected in CLAUDE.md memory file'
        : `Found ${evidence.length} potential secret(s) in CLAUDE.md`,
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: false,
      fixDescription: 'Remove the secret from CLAUDE.md and rotate the credential — memory files are often committed to git',
    };
  },
};
