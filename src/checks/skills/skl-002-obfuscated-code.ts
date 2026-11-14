import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { findHighEntropyBlocks } from '../../analyzers/entropy.js';
import { OBFUSCATION_PATTERNS, analyzeObfuscation, isBenignEncodedData, isBinaryHexEscapes } from '../../analyzers/obfuscation.js';
import { ScanLimitError } from '../../core/file-limits.js';
import { readSkillText, skillFilesOf, skillsDirsOf, unreadableSkillFile } from './skill-files.js';
import { unlistableSkillDirs } from '../../core/utils.js';
import { markTestCode } from '../../analyzers/test-paths.js';
import { analysisEvasion } from '../../analyzers/ast-analyzer.js';
import { truncateSnippet } from '../../core/patterns.js';
import { maskEncodedLiterals } from '../../mcp/string-table.js';
import { probeCoversTree } from '../../core/probe-coverage.js';

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
              if (label === 'Hex escape sequence chain' && isBinaryHexEscapes(line)) continue;
              if (label === 'atob() decoding' && !hasEncodedLiterals) continue;
              // Avoid duplicate evidence on the same line
              if (!reportedLines.has(i + 1)) {
                reportedLines.add(i + 1);
                evidence.push({
                  file,
                  line: i + 1,
                  // Decoded, an encoded literal is the value it hides
                  snippet: truncateSnippet(maskEncodedLiterals(line.trim())),
                  detail: `Pattern match: ${label}`,
                });
              }
            }
          }
        }

        // Code built to overflow the parser hides itself from the AST checks
        const evasion = analysisEvasion(code, file);
        if (evasion !== undefined) {
          const deep = evasion.line;
          const text = (lines[deep - 1] ?? '').trim();
          evidence.push({
            file,
            line: deep,
            snippet: truncateSnippet(text),
            detail: evasion.whole
            ? 'The file is nested or chained deeply enough to overflow the JavaScript parser and could not be analysed — only a line-by-line scan for exec and exfiltration calls ran'
            : 'Code nested or chained deeply enough to crash the JavaScript parser (brackets, templates, `?:`/`!` chains) or flood it with syntax errors — the statement is skipped by the other skill checks',
          });
        }
      } catch (err) {
        // Padding a file past the size limit hides it from every content
        // check — reported here once (informational) so it stays visible.
        if (err instanceof ScanLimitError) evidence.push({ file, detail: err.detail, mitigated: true });
        // So does a file the scan can't read
        const unreadable = unreadableSkillFile(file, err);
        if (unreadable) evidence.push(unreadable);
      }
    }

    // A skill directory the scan can't list (mode 111) hides its scripts from
    // every check while the agent still loads its SKILL.md by name
    for (const skillsDir of skillsDirsOf(ctx)) {
      for (const dir of await unlistableSkillDirs(skillsDir, ctx.fs)) {
        // Mode 000 (no search bit either) can't be entered: not even the
        // agent, running as this user, reads its SKILL.md
        const enterable = await ctx.fs.stat(dir).then(st => (st.mode & 0o111) !== 0, () => true);
        evidence.push({
          file: dir,
          detail: enterable
            ? 'Skill directory can be entered but not listed — its files are hidden from review and from these checks (the agent still loads SKILL.md by name)'
            : 'Skill directory can\'t be read or entered — its files are hidden from review and from these checks (an agent running with more privileges than this scan still loads them)',
        });
      }
    }

    // A skills directory a config points outside the remote probe's trees (a
    // Nanobot/PicoClaw/ZeroClaw workspace set in its config) isn't in the
    // snapshot: whatever it holds was not scanned. Informational — it may not
    // exist at all — but never passed as reviewed.
    for (const skillsDir of skillsDirsOf(ctx)) {
      if (probeCoversTree(ctx.fs, skillsDir) || await ctx.fs.access(skillsDir)) continue;
      evidence.push({
        file: skillsDir,
        detail: 'not scanned: skills directory not collected by the remote probe (set outside its default locations) — not verified; scan the host locally to check these skills',
        mitigated: true,
      });
    }

    await markTestCode(evidence, ctx.installation, ctx.fs);
    const notScanned = evidence.filter(e => e.line === undefined).length;
    return h.fromEvidence(evidence, {
      passed: 'No obfuscated code blocks detected',
      failed: (n) => {
        const blocks = n - notScanned;
        const parts = [
          ...(blocks > 0 ? [`${blocks} obfuscated code block(s) — possible obfuscation`] : []),
          ...(notScanned > 0 ? [`${notScanned} skill location(s) not scanned`] : []),
        ];
        return `Found ${parts.join('; ')}`;
      },
    });
  },
});
