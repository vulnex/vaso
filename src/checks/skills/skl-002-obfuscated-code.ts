import { dirname } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { findHighEntropyBlocks } from '../../analyzers/entropy.js';
import { OBFUSCATION_PATTERNS, analyzeObfuscation, isBenignEncodedData, isBinaryHexEscapes } from '../../analyzers/obfuscation.js';
import { ScanLimitError } from '../../core/file-limits.js';
import { skillFilesOf, skillsDirsOf, skillUnlistableDirsOf, unreadableSkillFile, unscannedShort, MAX_LISTED_IN_MESSAGE } from './skill-files.js';
import { jsAnalyzerName, readSkillSource, vendorFolderRefs } from './skill-source.js';
import { unlistableSkillDirs } from '../../core/utils.js';
import { markTestCode } from '../../analyzers/test-paths.js';
import { analysisEvasion } from '../../analyzers/ast-analyzer.js';
import { truncateSnippet } from '../../core/patterns.js';
import { maskEncodedLiterals } from '../../mcp/string-table.js';
import { configTreeGap, probeCoversTree } from '../../core/probe-coverage.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { missingRootReason, unscannedReason, unscannedRootMissing } from '../../core/skill-root-scope.js';

/** A URL (`https://…`, `<https://…>`) or a Markdown link target (`](…)`). */
const LINK = /<?\bhttps?:\/\/[^\s"'`<>]+>?|\]\([^)\s]+\)/g;

/** Markdown text with its URLs and link targets blanked (lines kept). */
export function withoutLinks(text: string): string {
  return text.replace(LINK, '');
}

export const skl002 = defineCheck({
  id: 'SKL-002',
  name: 'Obfuscated Code',
  category: 'skills',
  severity: 'warning',
  description: 'Detect obfuscated code using Shannon entropy analysis and pattern matching',

  async run(ctx, h) {
    const unscannedRoots = ctx.installation.unscannedSkillsDirs ?? [];
    if (skillsDirsOf(ctx).length === 0 && unscannedRoots.length === 0) return h.passed('No skills directory found');

    const evidence: Evidence[] = [];
    const files = await skillFilesOf(ctx);

    for (const file of files) {
      try {
        // Scripts and documentation code blocks: data files (lockfiles,
        // datasets, fixtures) are high-entropy by nature and run nowhere
        const src = await readSkillSource(ctx, file, 'patterns', 'blocks', { data: false });
        if (src === undefined || src.kind === 'data' || src.kind === 'manifest') continue;
        const code = src.text;

        const lines = code.split('\n');

        // Entropy-based detection. Data URIs and integrity digests are
        // high-entropy by nature, not hidden code; so are the links of
        // documentation (signed asset URLs, `[x](…)` targets)
        const blocks = findHighEntropyBlocks(src.kind === 'markdown' ? withoutLinks(code) : code)
          .filter(b => !isBenignEncodedData(lines[b.line - 1]));
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
        const evasion = src.lang === 'js' ? analysisEvasion(code, jsAnalyzerName(src)) : undefined;
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
        // A skill file over the size limit is not scanned, like a binary one
        // (BinarySkillFile): padding a script past the limit must not turn
        // its findings into an info. What a probe left out for its budget or
        // as metadata stays informational (the host warning says so).
        if (err instanceof ScanLimitError) evidence.push({ file, detail: err.detail, ...(err.reason === 'size' ? {} : { mitigated: true }) });
        // So does a file the scan can't read
        const unreadable = unreadableSkillFile(file, err);
        if (unreadable) evidence.push(unreadable);
      }
    }

    // A vendor folder a SKILL.md runs (`node node_modules/helper`): the walk
    // skips vendor dirs and reads only the files a SKILL.md names there
    for (const { dir, skillMd } of await vendorFolderRefs(ctx)) {
      evidence.push({
        file: dir,
        detail: `not scanned: vendor folder run by ${skillMd} — vendor folders are skipped, only the files a SKILL.md names in them are read`,
      });
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
    // A tree the probe refused or capped may still be in the snapshot in part
    // (another agent's files below it): judged before whether it exists.
    // A folder inside a skill the walk could not list: the files in it went
    // unread, so "no obfuscated code" would be a verdict on what wasn't seen
    // A skill installed as a link to such a folder is the skill itself
    const roots = new Set(skillsDirsOf(ctx));
    for (const dir of await skillUnlistableDirsOf(ctx)) {
      evidence.push({
        file: dir,
        detail: roots.has(dirname(dir))
          ? 'not scanned: skill installed as a link to a folder that can\'t be listed — its files are hidden from review and from these checks (an agent running with more privileges than this scan still loads them)'
          : 'not scanned: folder inside a skill can\'t be listed — its files are hidden from review and from these checks (an agent running with more privileges than this scan still loads them)',
      });
    }

    for (const skillsDir of skillsDirsOf(ctx)) {
      const gap = configTreeGap(ctx.fs, skillsDir);
      if (gap) {
        evidence.push({ file: skillsDir, detail: unscannedReason(gap === 'refused' ? 'outside' : gap, skillsDir), mitigated: true });
        continue;
      }
      // A skills directory that can't be listed (mode 000 or 111) hides
      // every skill in it, as a skill directory that can't be listed does
      if (await rootDenied(ctx.fs, skillsDir)) {
        evidence.push({
          file: skillsDir,
          detail: 'not scanned: skills directory can\'t be listed — the skills in it are hidden from review and from these checks (an agent running with more privileges than this scan still loads them)',
        });
        continue;
      }
      if (probeCoversTree(ctx.fs, skillsDir) || await ctx.fs.access(skillsDir)) continue;
      evidence.push({
        file: skillsDir,
        detail: 'not scanned: skills directory not collected by the remote probe (set outside its default locations) — not verified; scan the host locally to check these skills',
        mitigated: true,
      });
    }
    // Skills directories the config sets where no scan walks (outside the
    // home, a credential store, over the probe's limit, a relative path):
    // the agent loads whatever they hold, unreviewed — a warning, reported
    // here once per directory (the other skill checks say "not verified")
    // One that doesn't exist holds nothing to load: noted, informational
    const missingRoots: typeof unscannedRoots = [];
    for (const root of unscannedRoots) {
      if (await unscannedRootMissing(ctx.fs, root)) {
        missingRoots.push(root);
        evidence.push({ file: root.path, detail: missingRootReason(root), mitigated: true });
      } else {
        evidence.push({ file: root.path, detail: unscannedReason(root.reason, root.path, root) });
      }
    }

    await markTestCode(evidence, ctx.installation, ctx.fs);
    const notScanned = evidence.filter(e => e.line === undefined).length;
    const rootNote = unscannedRoots.map(u => `${u.skillLink ? 'skill' : 'skills directory'} ${u.path} not scanned (${unscannedShort(u)}${missingRoots.includes(u) ? '; no such directory' : ''})`);
    return h.fromEvidence(evidence, {
      passed: 'No obfuscated code blocks detected',
      failed: (n) => {
        const blocks = n - notScanned;
        const otherLocations = notScanned - unscannedRoots.length;
        const parts = [
          ...(blocks > 0 ? [`${blocks} obfuscated code block(s) — possible obfuscation`] : []),
          ...(otherLocations > 0 ? [`${otherLocations} skill location(s) not scanned`] : []),
        ];
        const found = parts.length > 0 ? `Found ${parts.join('; ')}` : '';
        const notes = rootNote.length > MAX_LISTED_IN_MESSAGE
          ? [...rootNote.slice(0, MAX_LISTED_IN_MESSAGE), `… and ${rootNote.length - MAX_LISTED_IN_MESSAGE} more not scanned (listed in the evidence)`]
          : rootNote;
        return [found, ...notes].filter(Boolean).join('; ');
      },
    });
  },
});

/** Listing the skills directory `dir` fails for permission (EACCES/EPERM). */
async function rootDenied(fs: FSProvider, dir: string): Promise<boolean> {
  try {
    await fs.readdirEntries(dir);
    return false;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | null)?.code;
    return code === 'EACCES' || code === 'EPERM';
  }
}

/** `path` is a directory (a snapshot knows it for a tree the probe judged). */
export async function isDirectory(fs: FSProvider, path: string): Promise<boolean> {
  return fs.stat(path).then(st => st.isDirectory(), () => false);
}
