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

import { API_KEY_PATTERNS } from '../core/patterns.js';

export interface ObfuscationPattern {
  pattern: RegExp;
  label: string;
}

/** Encoded-data indicators. Also consumed by SKL-002 over skill files. */
export const OBFUSCATION_PATTERNS: ObfuscationPattern[] = [
  { pattern: /(\\x[0-9a-fA-F]{2}){6,}/, label: 'Hex escape sequence chain' },
  { pattern: /[A-Za-z0-9+/]{60,}={0,2}/, label: 'Long base64-encoded string' },
  // Bounded argument spans: a lazy [\s\S]*? rescanned the rest of the line from
  // every call, quadratic on a multi-megabyte line of them
  { pattern: /String\.fromCharCode\s*\(\s*[^,()]{0,100},\s*[^,()]{0,100},/, label: 'String.fromCharCode with multiple args' },
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

/** A quoted base64-alphabet literal long enough to plausibly hold a hidden string. */
const ENCODED_LITERAL = /['"`]([A-Za-z0-9+/]{16,}={0,2})['"`]/g;

/**
 * Whether a base64-alphabet literal is actually shaped like base64 rather
 * than an identifier, path or hash that happens to use the same characters
 * (`"authorizationEndpointUrl"`, `"/usr/local/bin/node"`, a hex digest): padded
 * or a whole number of 4-char groups, mixed case, and dense in case switches
 * and digits, and not a run of camelCase/PascalCase words. camelCase words sit
 * near 0.2 on that density; base64 of text sits around 0.45.
 */
export function looksBase64Encoded(literal: string): boolean {
  if (!(literal.endsWith('=') || literal.length % 4 === 0)) return false;
  if (!/[a-z]/.test(literal) || !/[A-Z]/.test(literal)) return false;
  // camelCase / PascalCase identifiers (`UntitledSingleSelectEnumSchema`)
  // switch case at every word boundary; base64 has runs of capitals.
  if (/^(?:[A-Z]?[a-z]+\d*)+$/.test(literal)) return false;
  let signal = 0;
  for (let i = 0; i < literal.length; i++) {
    const c = literal[i];
    if (c >= '0' && c <= '9') { signal++; continue; }
    const p = literal[i - 1];
    if (!p || !/[A-Za-z]/.test(c) || !/[A-Za-z]/.test(p)) continue;
    if ((c >= 'a') !== (p >= 'a')) signal++;
  }
  return signal / literal.length >= 0.3;
}

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
  /** What a confirmed string-table hides, once decoded (string-table tier only). */
  revealed?: RevealedStrings;
}

/**
 * Kinds of value found in the decoded literals — domains and hosts, never the
 * values themselves, so a report doesn't republish what the code hid.
 */
export interface RevealedStrings {
  emailDomains: string[];
  urlHosts: string[];
  secretKinds: string[];
}

function decodeBase64Text(literal: string): string | undefined {
  const text = Buffer.from(literal, 'base64').toString('utf8');
  // Binary or mis-decoded data isn't a hidden string.
  const printable = [...text].filter((c) => c >= ' ' && c !== '\uFFFD').length;
  return text.length > 0 && printable / text.length >= 0.9 ? text : undefined;
}

function reveal(literals: string[]): RevealedStrings {
  const emailDomains = new Set<string>();
  const urlHosts = new Set<string>();
  const secretKinds = new Set<string>();
  for (const literal of literals) {
    const text = decodeBase64Text(literal);
    if (!text) continue;
    for (const m of text.matchAll(/[\w.+-]+@([\w-]+(?:\.[\w-]+)+)/g)) emailDomains.add(m[1].toLowerCase());
    for (const m of text.matchAll(/https?:\/\/([\w.-]+)/g)) urlHosts.add(m[1].toLowerCase());
    for (const { pattern, name } of API_KEY_PATTERNS) {
      if (pattern.test(text)) secretKinds.add(name);
    }
  }
  return { emailDomains: [...emailDomains], urlHosts: [...urlHosts], secretKinds: [...secretKinds] };
}

/**
 * Long base64-alphabet runs that are ordinary data, not hidden strings: data
 * URIs and embedded images (PNG/GIF/JPEG/WebP/SVG base64 headers), character
 * alphabets for ID generators, integrity digests, and hex digests / client IDs.
 */
const BENIGN_LONG_RUN = [
  /data:[\w.+/-]+;base64,/,
  // Subresource-integrity / npm lockfile `integrity` digests
  /\bsha(?:256|384|512)-[A-Za-z0-9+/]{40,}={0,2}/,
  /["'`](?:iVBORw0KGgo|R0lGOD|\/9j\/|UklGR|PHN2Zy|PD94bWwg)/,
  /ABCDEFGHIJKLMNOP|abcdefghijklmnop|0123456789/,
];
const LONG_RUN = /[A-Za-z0-9+/]{60,}={0,2}/g;

/** A line whose long base64-alphabet runs are all ordinary data (see BENIGN_LONG_RUN). */
export function isBenignEncodedData(line: string): boolean {
  if (BENIGN_LONG_RUN.some((re) => re.test(line))) return true;
  const runs = line.match(LONG_RUN) ?? [];
  // Hex digests / client IDs, and file paths (`node_modules/ajv/dist/…`):
  // every `/`-separated piece an ordinary word.
  const isPath = (run: string) => run.split('/').filter(Boolean).length >= 3 &&
    run.split('/').filter(Boolean).every((part) => /^[A-Za-z][a-z0-9]*(?:[A-Z][a-z0-9]*)*$/.test(part));
  // `0x`-prefixed too: hashes, Ethereum addresses, transaction ids
  const isHexDigest = (run: string) => /^(?:0x)?[0-9a-f]+$/i.test(run) && /\d/.test(run) && /[a-f]/i.test(run);
  return runs.length > 0 && runs.every((run) => isHexDigest(run) || isPath(run));
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
  const encodedLiterals: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isComment(line)) continue;

    for (const m of line.matchAll(ENCODED_LITERAL)) {
      if (looksBase64Encoded(m[1])) encodedLiterals.push(m[1]);
    }

    for (const { pattern, label } of OBFUSCATION_PATTERNS) {
      if (pattern.test(line)) {
        if (label === 'Long base64-encoded string' && isBenignEncodedData(line)) break;
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

  const encodedLiteralCount = encodedLiterals.length;
  let tier: ObfuscationReport['tier'] = 'none';
  if (decoderLabels.length > 0 && encodedLiteralCount >= STRING_TABLE_MIN_LITERALS) {
    tier = 'string-table';
  } else if (hits.length > 0) {
    tier = 'encoded';
  }

  const report: ObfuscationReport = { tier, decoderLabels, encodedLiteralCount, hits };
  if (tier === 'string-table') report.revealed = reveal(encodedLiterals);
  return report;
}
