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

// `Buffer.from(` is tried only when no earlier one in the same argument run
// (no `,`/`)` between) precedes it (the lookbehind): `[^,)]*` from either
// stops at the same `,`, so later ones decide nothing new and retrying each
// was quadratic on a line of thousands of `Buffer.from(` (100 KB: 0.4 s).
const DECODERS: Decoder[] = [
  { re: /Buffer\.from\s*\((?<!Buffer\.from\s*\([^,)]*?Buffer\.from\s*\()[^,)]*,\s*['"`](?:base64|base64url)['"`]\s*\)/, label: "Buffer.from(…, 'base64')", encodings: ['base64'] },
  { re: /Buffer\.from\s*\((?<!Buffer\.from\s*\([^,)]*?Buffer\.from\s*\()[^,)]*,\s*['"`]hex['"`]\s*\)/, label: "Buffer.from(…, 'hex')", encodings: ['hex'] },
  // Encoding named by a variable (`const ENC = "base" + "64"`) — any of them.
  { re: /Buffer\.from\s*\((?<!Buffer\.from\s*\([^,)]*?Buffer\.from\s*\()[^,)]*,\s*[A-Za-z_$][\w$.]*\s*\)\s*\.toString\s*\(/, label: 'Buffer.from(…, <encoding>)', encodings: ['base64', 'hex'] },
  { re: /\batob\s*\(/, label: 'atob()', encodings: ['base64'] },
  // Arguments bounded, without a separate leading-space run (`\(\s*[^)]*`
  // split a long space run every way: 100 KB, 11 s)
  { re: /\bTextDecoder\s*\([^)]{0,1000}\)\s*\.decode\s*\(|\bparseInt\s*\(\s*\w+\s*,\s*16\s*\)/, label: 'TextDecoder/parseInt hex decoding', encodings: ['hex'] },
  { re: /String\.fromCharCode\s*\(\s*\.\.\.|String\.fromCharCode\.apply\s*\(|\.map\s*\(\s*(?:\(?\w+\)?\s*=>\s*)?String\.fromCharCode\b/, label: 'String.fromCharCode() over an array', encodings: ['charcodes'] },
  { re: /charCodeAt\s*\(\s*(?:\d+\s*)?\)\s*\+\s*13\b|\brot13\b|['"`]rot_?13['"`]/i, label: 'rot13', encodings: ['rot13'] },
  // Python
  { re: /\b(?:b64decode|urlsafe_b64decode|standard_b64decode|a2b_base64)\s*\(/, label: 'base64.b64decode()', encodings: ['base64'] },
  { re: /\bbytes\.fromhex\s*\(|\bunhexlify\s*\(|\bb16decode\s*\(|\bcodecs\.decode\s*\([^)]*['"]hex['"]/, label: 'bytes.fromhex()', encodings: ['hex'] },
  // `"".join(map(chr, [...]))`, `chr(c) for c in [...]`, `bytes([...]).decode()`, `bytearray([...])`
  { re: /\bmap\s*\(\s*chr\s*,|\bchr\s*\(\s*\w+\s*\)\s*for\b|\b(?:bytes|bytearray)\s*\(\s*\[/, label: 'chr()/bytes() over a list', encodings: ['charcodes'] },
];

/** A literal's body worth decoding: 8+ characters with no escapes. */
const PLAIN_BODY = /^[^\\\n]{8,}$/;

/**
 * The string literals on one source line, in order, as the language's own
 * tokenizer sees them: a quote opens a literal only outside another one, and
 * an escaped quote doesn't close it. A regex pairing quotes left to right
 * read `"POST", k=Buffer.from("…")` as the literal `, k=Buffer.from(`. Line
 * comments end the scan; a `/` where an operand is expected starts a regex
 * literal, whose quotes are skipped too.
 */
export function lineStringLiterals(line: string): Array<{ quote: string; body: string; index: number }> {
  const out: Array<{ quote: string; body: string; index: number }> = [];
  let prev = ''; // last significant character outside literals
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"' || c === "'" || c === '`') {
      let j = i + 1;
      while (j < line.length && line[j] !== c) j += line[j] === '\\' ? 2 : 1;
      if (j >= line.length) break; // unterminated (a multi-line template, or not code)
      out.push({ quote: c, body: line.slice(i + 1, j), index: i });
      i = j;
      prev = c;
      continue;
    }
    if (c === '/' && line[i + 1] === '/') break;
    if (c === '/' && line[i + 1] === '*') {
      const end = line.indexOf('*/', i + 2);
      if (end < 0) break;
      i = end + 1;
      continue;
    }
    if (c === '/' && (prev === '' || /[(,=:[!&|?{};+\-*%<>~^]/.test(prev))) {
      // a regex literal: to its closing `/`, past escapes and character classes
      let j = i + 1;
      let inClass = false;
      while (j < line.length && (inClass || line[j] !== '/')) {
        if (line[j] === '\\') j++;
        else if (line[j] === '[') inClass = true;
        else if (line[j] === ']') inClass = false;
        j++;
      }
      i = j;
      prev = '/';
      continue;
    }
    if (!/\s/.test(c)) prev = c;
  }
  return out;
}
/**
 * A quoted literal written mostly as `\xNN` / `\uNNNN` / octal escapes — the JavaScript
 * or Python parser is its decoder, so it needs no decode call. Escaped quotes
 * and other escapes are consumed whole; the literal ends at its own quote.
 */
const ESCAPED_LITERAL = /(['"`])((?:\\[\s\S]|(?!\1)[^\\\n])*)\1/g;
/** `\xNN`, `\uNNNN`, `\u{N…}` and three-digit octal `\NNN` (Python, legacy JavaScript). */
const ESCAPE_UNIT = /\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]{1,6}\}|\\[0-7]{3}/g;
/** `String.fromCharCode(115, 107, …)` — decimal or `0x` codes as literal arguments. */
const CHAR_CODE_CALL = /String\.fromCharCode\s*\(\s*((?:(?:0x[0-9a-fA-F]{1,4}|\d{1,5})\s*,\s*){5,}(?:0x[0-9a-fA-F]{1,4}|\d{1,5}))\s*(?:,\s*)?\)/g;
/**
 * Encoding-alphabet chunks glued back together before decoding, so no single
 * literal is long enough to look encoded: `["c2st", "YW50"].join("")`,
 * `"c2st" + "YW50"` and `"\x73\x6b" + "\x2d\x61"`. The chunk literal is
 * quote-delimited and its alternatives disjoint, so the repetition can't
 * backtrack into itself.
 */
const CHUNK_BODY = String.raw`(?:[A-Za-z0-9+/=_-]|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})+`;
const JOINED_ARRAY = new RegExp(String.raw`\[\s*((['"${'`'}])${CHUNK_BODY}\2(?:\s*,\s*(['"${'`'}])${CHUNK_BODY}\3)+)\s*(?:,\s*)?\]\s*\.join\s*\(\s*(['"${'`'}])\4\s*\)`, 'g');
const CONCATENATED = new RegExp(String.raw`(['"${'`'}])${CHUNK_BODY}\1(?:\s*\+\s*(['"${'`'}])${CHUNK_BODY}\2)+`, 'g');
const CHUNK_TEXT = new RegExp(String.raw`(['"${'`'}])(${CHUNK_BODY})\1`, 'g');
/**
 * The code with chunked encoded literals glued back into one literal, each
 * replacement padded with the newlines it swallowed so line numbers hold.
 */
export function foldEncodedChunks(code: string): string {
  if (!code.includes('join') && !code.includes('+')) return code;
  const glue = (m: string, body: string) => {
    const joined = [...body.matchAll(CHUNK_TEXT)].map((c) => c[2]).join('');
    return `"${joined}"${'\n'.repeat(m.split('\n').length - 1)}`;
  };
  return code
    .replace(JOINED_ARRAY, (m: string, body: string) => glue(m, body))
    .replace(CONCATENATED, (m: string) => glue(m, m));
}

function decodeEscapes(body: string): string | undefined {
  const units = body.match(ESCAPE_UNIT) ?? [];
  if (units.length < 6) return undefined;
  const text = body.replace(/\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|u\{[0-9a-fA-F]{1,6}\}|[0-7]{1,3}|[\s\S])/g, (_m, e: string) => {
    if (e[0] === 'x') return String.fromCharCode(parseInt(e.slice(1), 16));
    if (/^[0-7]/.test(e)) return String.fromCharCode(parseInt(e, 8));
    if (e.length > 1 && e[0] === 'u') return String.fromCodePoint(parseInt(e.replace(/[u{}]/g, ''), 16));
    return ({ n: '\n', t: '\t', r: '\r' } as Record<string, string>)[e] ?? e;
  });
  // Mostly escapes: `"\x1b[31merror"` styling a word is not a hidden string
  return units.length * 2 >= text.length && readable(text) ? text : undefined;
}

function decodeCharCodes(list: string): string | undefined {
  const codes = list.split(',').map((n) => Number(n.trim()));
  if (!codes.every((n) => n >= 9 && n <= 126)) return undefined;
  const text = String.fromCharCode(...codes);
  return readable(text) ? text : undefined;
}

/** A decode call right before a literal: the literal is what it decodes. */
const DECODE_CALL_BEFORE = /(?:Buffer\.from|atob|b64decode|urlsafe_b64decode|standard_b64decode|a2b_base64|bytes\.fromhex|unhexlify|b16decode)\s*\(\s*$/;
/**
 * A decoded value handed straight to code execution, a module load or the
 * network: `eval(atob("…"))`, `require(Buffer.from("…", "hex").toString())`.
 */
const SINK_BEFORE = /\b(?:eval|Function|exec|execSync|execFile|execFileSync|spawn|spawnSync|require|import|fetch|system|popen|exec_module|__import__)\s*\(\s*(?:new\s+)?(?:(?:Buffer\.from|atob|String\.fromCharCode|unescape|decodeURIComponent|escape|b64decode|bytes\.fromhex)\s*\(\s*)*$/;
/** A list of 8+ character codes, decimal or `0x` hex. */
const CHAR_CODE_ARRAY = /\[\s*((?:(?:\d{2,3}|0x[0-9a-fA-F]{2})\s*,\s*){7,}(?:\d{2,3}|0x[0-9a-fA-F]{2}))\s*,?\s*\]/g;
/** Decoded strings longer than this are embedded files/source maps, not hidden strings. */
const MAX_DECODED = 300;

function readable(text: string, max = MAX_DECODED): boolean {
  if (text.length < 4 || text.length > max) return false;
  let printable = 0;
  for (const c of text) if ((c >= ' ' && c <= '~') || c === '\n' || c === '\t') printable++;
  return printable / text.length >= 0.95 && /[A-Za-z]{2}/.test(text);
}

function decodeBase64(lit: string, max = MAX_DECODED): string | undefined {
  if (!/^[A-Za-z0-9+/_-]{12,}={0,2}$/.test(lit) || /^[0-9a-f]+$/i.test(lit)) return undefined;
  // Words and identifiers are rarely a valid, readable decoding; mixed case
  // or digits are a cheap pre-filter.
  if (!/[A-Z]/.test(lit) || !/[a-z]/.test(lit)) return undefined;
  const text = Buffer.from(lit.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('latin1');
  return readable(text, max) ? text : undefined;
}

function decodeHex(lit: string, max = MAX_DECODED): string | undefined {
  if (!/^(?:[0-9a-fA-F]{2}){8,}$/.test(lit)) return undefined;
  const text = Buffer.from(lit, 'hex').toString('latin1');
  return readable(text, max) ? text : undefined;
}

function rot13(s: string): string {
  return s.replace(/[a-z]/gi, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

/** A decoded value that is evidently a hidden endpoint, secret or command. */
const REVEALING = /https?:\/\/|\b(?:curl|wget|bash|powershell|nc|chmod)\b|\/bin\/|[\w.+-]+@[\w-]+\.[\w.]+/;
/** Decoded code: a module load, process/shell access or dynamic evaluation. */
const CODE_LIKE = /\brequire\s*\(|\bimport\s*\(|\bchild_process\b|\beval\s*\(|\bnew\s+Function\b|\bprocess\.(?:env|mainModule|binding)\b|\b(?:execSync|spawnSync|execFile)\b|\bsubprocess\b|\bos\.(?:system|popen)\b|__import__|\b(?:sh|python3?|node)\s+-[ce]\b/;

/** A decoded value that is a hidden endpoint, command, credential or code. */
function revealing(text: string): boolean {
  return REVEALING.test(text) || CODE_LIKE.test(text) || API_KEY_PATTERNS.some(({ pattern }) => pattern.test(text));
}

export interface StringTableReport {
  confirmed: boolean;
  decoderLabels: string[];
  /** Literals that decode to readable text under an encoding the code decodes. */
  decodedCount: number;
  revealed: RevealedStrings;
  /** Lines holding the decoded literals (first few). */
  lines: number[];
  /**
   * Lines holding a literal handed straight to a decode call (or written as
   * escapes / char codes) that decodes to ordinary text — encoding with no
   * confirmed purpose, informational (unconfirmed findings only).
   */
  inertLines: number[];
}

/** Longest decoded value read when it goes straight into eval/exec/require/fetch. */
const MAX_DECODED_AT_SINK = 64 * 1024;

interface Decoded { text: string; line: number; direct: boolean; sink: boolean }

export function analyzeStringTable(code: string): StringTableReport {
  // Chunks joined at runtime are judged as the string they make
  code = foldEncodedChunks(code);
  const decoders = DECODERS.filter((d) => d.re.test(code));
  const encodings = new Set(decoders.flatMap((d) => d.encodings));
  const implicit = new Set<string>();
  const decoded: Decoded[] = [];
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const t = line.trimStart();
    if (t.startsWith('//') || t.startsWith('#') || t.startsWith('*')) continue;
    let tokens: ReturnType<typeof lineStringLiterals> | undefined;
    const literals = () => (tokens ??= lineStringLiterals(line));
    const at = (index: number) => {
      const before = line.slice(Math.max(0, index - 120), index);
      return { direct: DECODE_CALL_BEFORE.test(before), sink: SINK_BEFORE.test(before) };
    };
    if (encodings.size > 0) {
      for (const literal of literals()) {
        if (!PLAIN_BODY.test(literal.body)) continue;
        const lit = literal.body;
        const { direct, sink } = at(literal.index);
        const max = sink ? MAX_DECODED_AT_SINK : MAX_DECODED;
        const text = (encodings.has('hex') ? decodeHex(lit, max) : undefined)
          ?? (encodings.has('base64') ? decodeBase64(lit, max) : undefined)
          ?? (encodings.has('rot13') && REVEALING.test(rot13(lit)) && !REVEALING.test(lit) ? rot13(lit) : undefined);
        if (text) decoded.push({ text, line: i + 1, direct, sink });
      }
      if (encodings.has('charcodes')) {
        for (const m of line.matchAll(CHAR_CODE_ARRAY)) {
          const text = decodeCharCodes(m[1]);
          if (text) decoded.push({ text, line: i + 1, direct: false, sink: false });
        }
      }
    }
    // Decoded by the parser or a char-code call — no separate decoder needed
    if (/\\(?:[xu]|[0-7]{3})/.test(line)) {
      for (const literal of literals()) {
        const text = decodeEscapes(literal.body);
        if (!text) continue;
        implicit.add('hex/unicode/octal-escaped string literal');
        decoded.push({ text, line: i + 1, direct: true, sink: at(literal.index).sink });
      }
    }
    if (line.includes('fromCharCode')) {
      for (const m of line.matchAll(CHAR_CODE_CALL)) {
        const text = decodeCharCodes(m[1]);
        if (!text) continue;
        implicit.add('String.fromCharCode(<char codes>)');
        decoded.push({ text, line: i + 1, direct: true, sink: at(m.index).sink });
      }
    }
  }
  const distinct = [...new Map(decoded.map((d) => [d.text, d])).values()];
  const decoderLabels = [...decoders.map((d) => d.label), ...implicit];
  const confirmed = decoderLabels.length > 0
    && (distinct.length >= 3 || distinct.some((d) => d.sink || revealing(d.text)));
  return {
    confirmed,
    decoderLabels,
    decodedCount: distinct.length,
    revealed: reveal(distinct.map((d) => d.text)),
    lines: distinct.slice(0, 5).map((d) => d.line),
    inertLines: confirmed ? [] : [...new Set(distinct.filter((d) => d.direct).map((d) => d.line))].slice(0, 5),
  };
}

const MASK_BASE64 = /(["'`])[A-Za-z0-9+/_=-]{16,}\1/g;

/**
 * A source line with every encoded literal replaced by its length — decoded,
 * they are the values (keys, URLs, commands) a report must never print:
 * base64/hex literals (chunked ones glued first), `\x`/`\u` escaped strings
 * and char-code lists. Applied before a snippet is truncated, so a cut can't
 * leave the start of one behind.
 */
export function maskEncodedLiterals(line: string): string {
  let out = foldEncodedChunks(line);
  if (/\\(?:[xu]|[0-7]{3})/.test(out)) {
    out = out.replace(ESCAPED_LITERAL, (m, q: string, body: string) =>
      (body.match(ESCAPE_UNIT) ?? []).length >= 2 ? `${q}<encoded, ${body.length} chars>${q}` : m);
  }
  out = out
    .replace(CHAR_CODE_CALL, (_m, list: string) => `String.fromCharCode(<${list.split(',').length} char codes>)`)
    .replace(CHAR_CODE_ARRAY, (_m, list: string) => `[<${list.split(',').length} char codes>]`);
  return out.replace(MASK_BASE64, (m, q: string) => `${q}<encoded, ${m.length - 2} chars>${q}`);
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
