/**
 * Runtime-decoded string tables in MCP server source (MCP-035), judged by
 * what the literals decode to rather than how they look.
 *
 * The shared obfuscation analyzer (`analyzers/obfuscation.ts`, also used by
 * SKL-002) keys on padded base64-looking literals next to a decode call. That
 * misses the other encodings a string table uses — unpadded base64, base64url,
 * hex, rot13, char-code arrays, TextDecoder, Python `b64decode` /
 * `bytes.fromhex` — and it fires on bundles where `atob` decodes runtime data
 * and a few identifiers (`"SearchWixAPISpec"`) happen to look like base64.
 * Here a literal counts only if it decodes to readable text, which random
 * identifiers and digests don't.
 */

import { API_KEY_PATTERNS } from '../core/patterns.js';
import type { RevealedStrings } from '../analyzers/obfuscation.js';

interface Decoder {
  re: RegExp;
  label: string;
  encodings: Encoding[];
}

type Encoding = 'base64' | 'hex' | 'rot13' | 'charcodes';

const DECODERS: Decoder[] = [
  { re: /Buffer\.from\s*\([^,)]*,\s*['"`](?:base64|base64url)['"`]\s*\)/, label: "Buffer.from(…, 'base64')", encodings: ['base64'] },
  { re: /Buffer\.from\s*\([^,)]*,\s*['"`]hex['"`]\s*\)/, label: "Buffer.from(…, 'hex')", encodings: ['hex'] },
  // Encoding named by a variable (`const ENC = "base" + "64"`) — any of them.
  { re: /Buffer\.from\s*\([^,)]*,\s*[A-Za-z_$][\w$.]*\s*\)\s*\.toString\s*\(/, label: 'Buffer.from(…, <encoding>)', encodings: ['base64', 'hex'] },
  { re: /\batob\s*\(/, label: 'atob()', encodings: ['base64'] },
  // Arguments bounded, without a separate leading-space run (`\(\s*[^)]*`
  // split a long space run every way: 100 KB, 11 s)
  { re: /\bTextDecoder\s*\([^)]{0,1000}\)\s*\.decode\s*\(|\bparseInt\s*\(\s*\w+\s*,\s*16\s*\)/, label: 'TextDecoder/parseInt hex decoding', encodings: ['hex'] },
  { re: /String\.fromCharCode\s*\(\s*\.\.\.|String\.fromCharCode\.apply\s*\(|\.map\s*\(\s*\(?\w+\)?\s*=>\s*String\.fromCharCode\s*\(/, label: 'String.fromCharCode() over an array', encodings: ['charcodes'] },
  { re: /charCodeAt\s*\(\s*(?:\d+\s*)?\)\s*\+\s*13\b|\brot13\b|['"`]rot_?13['"`]/i, label: 'rot13', encodings: ['rot13'] },
  // Python
  { re: /\b(?:b64decode|urlsafe_b64decode|standard_b64decode|a2b_base64)\s*\(/, label: 'base64.b64decode()', encodings: ['base64'] },
  { re: /\bbytes\.fromhex\s*\(|\bunhexlify\s*\(|\bb16decode\s*\(|\bcodecs\.decode\s*\([^)]*['"]hex['"]/, label: 'bytes.fromhex()', encodings: ['hex'] },
];

const QUOTED = /(['"`])([^'"`\n\\]{8,})\1/g;
const CHAR_CODE_ARRAY = /\[\s*((?:\d{2,3}\s*,\s*){7,}\d{2,3})\s*,?\s*\]/g;
/** Decoded strings longer than this are embedded files/source maps, not hidden strings. */
const MAX_DECODED = 300;

function readable(text: string): boolean {
  if (text.length < 4 || text.length > MAX_DECODED) return false;
  let printable = 0;
  for (const c of text) if ((c >= ' ' && c <= '~') || c === '\n' || c === '\t') printable++;
  return printable / text.length >= 0.95 && /[A-Za-z]{2}/.test(text);
}

function decodeBase64(lit: string): string | undefined {
  if (!/^[A-Za-z0-9+/_-]{12,}={0,2}$/.test(lit) || /^[0-9a-f]+$/i.test(lit)) return undefined;
  // Words and identifiers are rarely a valid, readable decoding; mixed case
  // or digits are a cheap pre-filter.
  if (!/[A-Z]/.test(lit) || !/[a-z]/.test(lit)) return undefined;
  const text = Buffer.from(lit.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('latin1');
  return readable(text) ? text : undefined;
}

function decodeHex(lit: string): string | undefined {
  if (!/^(?:[0-9a-fA-F]{2}){8,}$/.test(lit)) return undefined;
  const text = Buffer.from(lit, 'hex').toString('latin1');
  return readable(text) ? text : undefined;
}

function rot13(s: string): string {
  return s.replace(/[a-z]/gi, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

/** A decoded value that is evidently a hidden endpoint, secret or command. */
const REVEALING = /https?:\/\/|\b(?:curl|wget|bash|powershell|nc|chmod)\b|\/bin\/|[\w.+-]+@[\w-]+\.[\w.]+/;

export interface StringTableReport {
  confirmed: boolean;
  decoderLabels: string[];
  /** Literals that decode to readable text under an encoding the code decodes. */
  decodedCount: number;
  revealed: RevealedStrings;
  /** Lines holding the decoded literals (first few). */
  lines: number[];
}

export function analyzeStringTable(code: string): StringTableReport {
  const decoders = DECODERS.filter((d) => d.re.test(code));
  const encodings = new Set(decoders.flatMap((d) => d.encodings));
  const decoded: Array<{ text: string; line: number }> = [];
  if (encodings.size > 0) {
    const lines = code.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const t = line.trimStart();
      if (t.startsWith('//') || t.startsWith('#') || t.startsWith('*')) continue;
      for (const m of line.matchAll(QUOTED)) {
        const lit = m[2];
        const text = (encodings.has('hex') ? decodeHex(lit) : undefined)
          ?? (encodings.has('base64') ? decodeBase64(lit) : undefined)
          ?? (encodings.has('rot13') && REVEALING.test(rot13(lit)) && !REVEALING.test(lit) ? rot13(lit) : undefined);
        if (text) decoded.push({ text, line: i + 1 });
      }
      if (encodings.has('charcodes')) {
        for (const m of line.matchAll(CHAR_CODE_ARRAY)) {
          const codes = m[1].split(',').map((n) => Number(n.trim()));
          if (codes.every((n) => n >= 9 && n <= 126)) {
            const text = String.fromCharCode(...codes);
            if (readable(text)) decoded.push({ text, line: i + 1 });
          }
        }
      }
    }
  }
  const distinct = [...new Map(decoded.map((d) => [d.text, d])).values()];
  const confirmed = decoders.length > 0 && (distinct.length >= 3 || distinct.some((d) => REVEALING.test(d.text)));
  return {
    confirmed,
    decoderLabels: decoders.map((d) => d.label),
    decodedCount: distinct.length,
    revealed: reveal(distinct.map((d) => d.text)),
    lines: distinct.slice(0, 5).map((d) => d.line),
  };
}

function reveal(texts: string[]): RevealedStrings {
  const emailDomains = new Set<string>();
  const urlHosts = new Set<string>();
  const secretKinds = new Set<string>();
  for (const text of texts) {
    for (const m of text.matchAll(/[\w.+-]+@([\w-]+(?:\.[\w-]+)+)/g)) emailDomains.add(m[1].toLowerCase());
    for (const m of text.matchAll(/https?:\/\/([\w.-]+)/g)) urlHosts.add(m[1].toLowerCase());
    for (const { pattern, name } of API_KEY_PATTERNS) if (pattern.test(text)) secretKinds.add(name);
  }
  return { emailDomains: [...emailDomains], urlHosts: [...urlHosts], secretKinds: [...secretKinds] };
}
