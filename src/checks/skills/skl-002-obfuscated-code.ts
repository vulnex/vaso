import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { findHighEntropyBlocks } from '../../analyzers/entropy.js';
import { OBFUSCATION_PATTERNS, isBenignEncodedData } from '../../analyzers/obfuscation.js';
import { OVER_LIMIT_DETAIL, ScanLimitError } from '../../core/file-limits.js';
import { readSkillText, skillFilesOf, skillsDirsOf } from './skill-files.js';
import { markTestCode } from '../../analyzers/test-paths.js';
import { ANALYSIS_NESTING_LIMIT, overNestedLines } from '../../analyzers/js-parse.js';

export const skl002 = defineCheck({
  id: 'SKL-002',
  name: 'Obfuscated Code',
  category: 'skills',
  severity: 'warning',
  description: 'Detect obfuscated code using Shannon entropy analysis and pattern matching',

  async run(ctx, h) {
    if (skillsDirsOf(ctx).length === 0) return h.passed('No skills directory found');

    const evidence: Evidence[] = [];
    const files = await skillFilesOf(ctx);

    for (const file of files) {
      try {
        const code = await readSkillText(ctx.fs, file, 'patterns');
        if (code === undefined) continue;

        const lines = code.split('\n');

        // Entropy-based detection. Data URIs and integrity digests are
        // high-entropy by nature, not hidden code.
        const blocks = findHighEntropyBlocks(code).filter(b => !isBenignEncodedData(lines[b.line - 1]));
        for (const block of blocks) {
          evidence.push({
            file,
            line: block.line,
            snippet: block.snippet,
            detail: `Entropy: ${block.entropy} bits/char (threshold: 5.5)`,
          });
        }

        // Pattern-based detection for obfuscation that entropy may miss
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (line.trimStart().startsWith('//') || line.trimStart().startsWith('#')) continue;
          for (const { pattern, label } of OBFUSCATION_PATTERNS) {
            if (pattern.test(line)) {
              if (label === 'Long base64-encoded string' && isBenignEncodedData(line)) continue;
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

        // Nesting past what the parser survives hides the file from the AST checks
        const deep = overNestedLines(code)[0];
        if (deep !== undefined) {
          const text = lines[deep - 1].trim();
          evidence.push({
            file,
            line: deep,
            snippet: text.slice(0, 80) + (text.length > 80 ? '...' : ''),
            detail: `Brackets nested more than ${ANALYSIS_NESTING_LIMIT} levels deep — enough to crash code analysis; the over-nested lines are skipped by the other skill checks`,
          });
        }
      } catch (err) {
        // Padding a file past the size limit hides it from every content
        // check — reported here once (informational) so it stays visible.
        if (err instanceof ScanLimitError) evidence.push({ file, detail: OVER_LIMIT_DETAIL, mitigated: true });
      }
    }

    await markTestCode(evidence, ctx.installation, ctx.fs);
    return h.fromEvidence(evidence, {
      passed: 'No obfuscated code blocks detected',
      failed: (n) => `Found ${n} obfuscated code block(s) — possible obfuscation`,
    });
  },
});
