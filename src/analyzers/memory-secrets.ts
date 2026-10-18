import type { Evidence, Severity } from '../core/types.js';
import { API_KEY_PATTERNS, isPlaceholderSecret } from '../core/patterns.js';
import { findHighEntropyBlocks } from './entropy.js';

/**
 * Plaintext-secret scan for the prose files coding agents load into every
 * prompt (CLAUDE.md, AGENTS.md, GEMINI.md, QWEN.md, copilot-instructions.md,
 * Devin rules files). Shared by CC-012, CDX-007, OPC-007, GEM-010, QC-010,
 * GHC-008 and DEV-007 so every agent recognises the same key formats —
 * including OpenAI's `sk-proj-`/`sk-svcacct-`/`sk-admin-` keys from
 * `API_KEY_PATTERNS`.
 *
 * Tiering (one rule for all memory checks): a recognised credential format
 * is critical — a live key sits in a file that is sent to the model and is
 * routinely committed; a high-entropy string with no known prefix is only a
 * possible secret, reported as a warning.
 */

/** Formats `API_KEY_PATTERNS` doesn't cover. */
const EXTRA_KEY_PATTERNS: { pattern: RegExp; name: string }[] = [
  { pattern: /github_pat_[A-Za-z0-9_]{20,}/, name: 'GitHub fine-grained PAT' },
  { pattern: /AIza[0-9A-Za-z_-]{30,}/, name: 'Google API key' },
  { pattern: /xox[aprs]-[A-Za-z0-9-]{10,}/, name: 'Slack token' },
];

// In prose a key starts at a word boundary: `disk-0123…` is not an `sk-` key.
// A lookbehind (not \b) so patterns starting with `-` keep matching.
const KNOWN_KEY_PATTERNS = [...API_KEY_PATTERNS, ...EXTRA_KEY_PATTERNS].map(({ pattern, name }) => ({
  pattern: new RegExp(`(?<![A-Za-z0-9_])(?:${pattern.source})`, pattern.flags),
  name,
}));

const ENTROPY_THRESHOLD = 5.5;
const MIN_BLOCK_LEN = 40;

/** Evidence items that are a recognised credential (vs. a high-entropy guess). */
const CREDENTIAL_EVIDENCE = new WeakSet<Evidence>();

/** Evidence for every plaintext credential (one per line) and high-entropy string in `content`. */
export function scanMemorySecrets(file: string, content: string, kind = 'memory file'): Evidence[] {
  const evidence: Evidence[] = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    for (const { pattern, name } of KNOWN_KEY_PATTERNS) {
      const m = pattern.exec(lines[i]);
      if (!m || isPlaceholderSecret(m[0])) continue;
      const item: Evidence = {
        file,
        line: i + 1,
        snippet: `${m[0].slice(0, 12)}…`,
        detail: `Plaintext ${name} in ${kind}`,
      };
      CREDENTIAL_EVIDENCE.add(item);
      evidence.push(item);
      break;
    }
  }

  for (const b of findHighEntropyBlocks(content, ENTROPY_THRESHOLD, MIN_BLOCK_LEN)) {
    if (evidence.some(e => e.line === b.line)) continue;
    evidence.push({
      file,
      line: b.line,
      snippet: b.snippet,
      detail: `High-entropy string (${b.entropy} bits) — possible embedded secret`,
    });
  }
  return evidence;
}

/** Critical when a live (unmitigated) item is a recognised credential, else warning. */
export function memorySecretSeverity(evidence: Evidence[]): Severity {
  return evidence.some(e => !e.mitigated && CREDENTIAL_EVIDENCE.has(e)) ? 'critical' : 'warning';
}
