import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { findHighEntropyBlocks } from '../../analyzers/entropy.js';
import { OBFUSCATION_PATTERNS, analyzeObfuscation, isBenignEncodedData } from '../../analyzers/obfuscation.js';
import { ScanLimitError } from '../../core/file-limits.js';
import { readSkillText, skillFilesOf, skillsDirsOf } from './skill-files.js';
import { unlistableSkillDirs } from '../../core/utils.js';
import { markTestCode } from '../../analyzers/test-paths.js';
import { analysisEvasion } from '../../analyzers/ast-analyzer.js';

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
        // One finding per line (a Set: scanning the evidence for each match was quadratic)
        const reportedLines = new Set(blocks.map(b => b.line));
        for (const block of blocks) {
          evidence.push({
            file,
            line: block.line,
            snippet: block.snippet,
            detail: `Entropy: ${block.entropy} bits/char (threshold: 5.5)`,
          });
        }

        // Pattern-based detection for obfuscation that entropy may miss
        // atob() decodes runtime data too (JWTs, data URLs); it only suggests
        // hidden strings when the file holds base64-shaped literals to decode
        const hasEncodedLiterals = analyzeObfuscation(code).encodedLiteralCount > 0;
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (line.trimStart().startsWith('//') || line.trimStart().startsWith('#')) continue;
          for (const { pattern, label } of OBFUSCATION_PATTERNS) {
            if (pattern.test(line)) {
              if (label === 'Long base64-encoded string' && isBenignEncodedData(line)) continue;
              if (label === 'atob() decoding' && !hasEncodedLiterals) continue;
              // Avoid duplicate evidence on the same line
              if (!reportedLines.has(i + 1)) {
                reportedLines.add(i + 1);
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

        // Code built to overflow the parser hides itself from the AST checks
        const deep = analysisEvasion(code, file);
        if (deep !== undefined) {
          const text = (lines[deep - 1] ?? '').trim();
          evidence.push({
            file,
            line: deep,
            snippet: text.slice(0, 80) + (text.length > 80 ? '...' : ''),
            detail: 'Code nested or chained deeply enough to crash the JavaScript parser (brackets, templates, `?:`/`!` chains) — the statement is skipped by the other skill checks',
          });
        }
      } catch (err) {
        // Padding a file past the size limit hides it from every content
        // check — reported here once (informational) so it stays visible.
        if (err instanceof ScanLimitError) evidence.push({ file, detail: err.detail, mitigated: true });
      }
    }

    // A skill directory the scan can't list (mode 111) hides its scripts from
    // every check while the agent still loads its SKILL.md by name
    for (const skillsDir of skillsDirsOf(ctx)) {
      for (const dir of await unlistableSkillDirs(skillsDir, ctx.fs)) {
        evidence.push({
          file: dir,
          detail: 'Skill directory can be entered but not listed — its files are hidden from review and from these checks (the agent still loads SKILL.md by name)',
        });
      }
    }

    await markTestCode(evidence, ctx.installation, ctx.fs);
    return h.fromEvidence(evidence, {
      passed: 'No obfuscated code blocks detected',
      failed: (n) => `Found ${n} obfuscated code block(s) — possible obfuscation`,
    });
  },
});
