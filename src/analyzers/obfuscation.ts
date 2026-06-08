/**
 * Obfuscation detection shared between skill code (SKL-002) and MCP server
 * source (MCP-035).
 *
 * Two distinct questions:
 *  - "Does this line contain encoded data?" — the OBFUSCATION_PATTERNS set
 *    (long base64, hex-escape chains, multi-arg fromCharCode, atob). SKL-002
 *    uses these directly alongside Shannon-entropy analysis.
 *  - "Is encoded data turned back into strings/code at runtime?" — the
 *    DECODER_PATTERNS set. A *decoder operating over a table of encoded
 *    literals* (e.g. `Buffer.from(t[i], 'base64')` over a 28-element array) is
 *    deliberate string-hiding: the URLs, secrets and commands the code actually
 *    uses never appear in clear, defeating static review. That combination is
 *    the high-confidence signal MCP-035 keys on; a lone encoded literal with no
 *    decoder is only suspicious, not confirmed.
 */

export interface ObfuscationPattern {
  pattern: RegExp;
  label: string;
}

/** Encoded-data indicators. Also consumed by SKL-002 over skill files. */
export const OBFUSCATION_PATTERNS: ObfuscationPattern[] = [
  { pattern: /(\\x[0-9a-fA-F]{2}){6,}/, label: 'Hex escape sequence chain' },
  { pattern: /[A-Za-z0-9+/]{60,}={0,2}/, label: 'Long base64-encoded string' },
  { pattern: /String\.fromCharCode\s*\([\s\S]*?,[\s\S]*?,/, label: 'String.fromCharCode with multiple args' },
  { pattern: /\batob\s*\(/, label: 'atob() decoding' },
];

/** Runtime decode calls — the "encoded data is turned back into strings" signal. */
const DECODER_PATTERNS: ObfuscationPattern[] = [
  { pattern: /Buffer\.from\s*\([^,)]*,\s*['"`]base64['"`]\s*\)/, label: "Buffer.from(…, 'base64')" },
  { pattern: /\batob\s*\(/, label: 'atob()' },
  { pattern: /String\.fromCharCode(?:\.apply)?\s*\(/, label: 'String.fromCharCode()' },
  { pattern: /\bunescape\s*\(/, label: 'unescape()' },
  { pattern: /\bdecodeURIComponent\s*\(\s*escape\s*\(/, label: 'decodeURIComponent(escape(…))' },
];

/** A quoted base64-ish literal long enough to plausibly hold a hidden string. */
const ENCODED_LITERAL = /['"`][A-Za-z0-9+/]{16,}={0,2}['"`]/g;

/** Lowest count of encoded literals that, with a decoder, reads as a string-table. */
const STRING_TABLE_MIN_LITERALS = 3;

export interface ObfuscationLineHit {
  line: number;
  snippet: string;
  label: string;
}

export interface ObfuscationReport {
  /**
   * - `string-table`: a decode call over a table of encoded literals (confirmed
   *   deliberate string-hiding — warning-worthy).
   * - `encoded`: encoded-data patterns present but no qualifying decoder/table
   *   (suspicious, not confirmed — informational).
   * - `none`: nothing of note.
   */
  tier: 'string-table' | 'encoded' | 'none';
  decoderLabels: string[];
  encodedLiteralCount: number;
  hits: ObfuscationLineHit[];
}

function isComment(line: string): boolean {
  const t = line.trimStart();
  return t.startsWith('//') || t.startsWith('*') || t.startsWith('#');
}

/**
 * Classify obfuscation in a source string. Entropy analysis is intentionally
 * *not* part of this — over server/dependency code, high entropy alone (hashes,
 * UUIDs, embedded data) is too noisy to act on. SKL-002 keeps its own entropy
 * pass for skill files; MCP-035 relies on the explicit encoding/decoder signals
 * here for precision.
 */
export function analyzeObfuscation(code: string): ObfuscationReport {
  const lines = code.split('\n');
  const hits: ObfuscationLineHit[] = [];
  let encodedLiteralCount = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isComment(line)) continue;

    const encoded = line.match(ENCODED_LITERAL);
    if (encoded) encodedLiteralCount += encoded.length;

    for (const { pattern, label } of OBFUSCATION_PATTERNS) {
      if (pattern.test(line)) {
        const trimmed = line.trim();
        hits.push({
          line: i + 1,
          snippet: trimmed.slice(0, 80) + (trimmed.length > 80 ? '...' : ''),
          label,
        });
        break;
      }
    }
  }

  const decoderLabels: string[] = [];
  for (const { pattern, label } of DECODER_PATTERNS) {
    if (pattern.test(code)) decoderLabels.push(label);
  }

  let tier: ObfuscationReport['tier'] = 'none';
  if (decoderLabels.length > 0 && encodedLiteralCount >= STRING_TABLE_MIN_LITERALS) {
    tier = 'string-table';
  } else if (hits.length > 0) {
    tier = 'encoded';
  }

  return { tier, decoderLabels, encodedLiteralCount, hits };
}
