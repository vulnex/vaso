import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { findHighEntropyBlocks } from '../../analyzers/entropy.js';
import { getSkillFiles } from '../../core/utils.js';

// Pattern-based obfuscation indicators that entropy alone may miss
const OBFUSCATION_PATTERNS: { pattern: RegExp; label: string }[] = [
  { pattern: /(\\x[0-9a-fA-F]{2}){6,}/, label: 'Hex escape sequence chain' },
  { pattern: /[A-Za-z0-9+/]{60,}={0,2}/, label: 'Long base64-encoded string' },
  { pattern: /String\.fromCharCode\s*\([\s\S]*?,[\s\S]*?,/, label: 'String.fromCharCode with multiple args' },
  { pattern: /\batob\s*\(/, label: 'atob() decoding' },
];

export const skl002 = defineCheck({
  id: 'SKL-002',
  name: 'Obfuscated Code',
  category: 'skills',
  severity: 'warning',
  description: 'Detect obfuscated code using Shannon entropy analysis and pattern matching',

  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed('No skills directory found');

    const evidence: Evidence[] = [];
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir);

    for (const file of files) {
      try {
        const code = await ctx.fs.readFile(file);

        // Entropy-based detection
        const blocks = findHighEntropyBlocks(code);
        for (const block of blocks) {
          evidence.push({
            file,
            line: block.line,
            snippet: block.snippet,
            detail: `Entropy: ${block.entropy} bits/char (threshold: 5.5)`,
          });
        }

        // Pattern-based detection for obfuscation that entropy may miss
        const lines = code.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (line.trimStart().startsWith('//') || line.trimStart().startsWith('#')) continue;
          for (const { pattern, label } of OBFUSCATION_PATTERNS) {
            if (pattern.test(line)) {
              // Avoid duplicate evidence on the same line
              const alreadyReported = evidence.some(e => e.file === file && e.line === i + 1);
              if (!alreadyReported) {
                evidence.push({
                  file,
                  line: i + 1,
                  snippet: line.trim().slice(0, 80) + (line.trim().length > 80 ? '...' : ''),
                  detail: `Pattern match: ${label}`,
                });
              }
            }
          }
        }
      } catch {}
    }

    return h.fromEvidence(evidence, {
      passed: 'No obfuscated code blocks detected',
      failed: (n) => `Found ${n} obfuscated code block(s) — possible obfuscation`,
    });
  },
});
