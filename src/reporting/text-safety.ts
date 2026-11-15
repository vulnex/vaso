/**
 * Text from scanned hosts (config values, file names, server names, the cwd
 * project name) is attacker-influenced. Written raw to a terminal, control
 * characters in it can clear the screen, forge hyperlinks (OSC 8) or retitle
 * the window; in XML some of them make the document invalid.
 */

// C0 controls except tab and newline, DEL, C1 controls (0x80–0x9f; 0x9b is
// CSI), the bidi embedding/override/isolate controls and marks (ALM, LRM,
// RLM), which reorder how a line displays (a file name or rule that reads
// differently than it is), and invisible characters — zero-width space and
// joiners, word joiner and invisible operators, BOM, Unicode tag characters
// (U+E0000–E007F, which spell hidden ASCII) — that make different strings
// print alike. The Unicode line and paragraph separators (U+2028/2029) are
// always shown escaped: only \n is a line break VASO's text keeps
const CONTROL_RE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\u{e0000}-\u{e007f}]/gu;

function visible(ch: string): string {
  const code = ch.codePointAt(0)!;
  if (code > 0xffff) return `\\u{${code.toString(16)}}`;
  return code > 0xff ? `\\u${code.toString(16).padStart(4, '0')}` : `\\x${code.toString(16).padStart(2, '0')}`;
}

/**
 * Control characters shown as `\xNN` (`\u2028`, …). Newlines are kept unless
 * `lineBreaks` is set, which shows them as `\n` — for single-line fields in
 * terminal output (a server name or rule containing one forges a report line).
 */
export function escapeControlChars(s: string, options?: { lineBreaks?: boolean }): string {
  const out = s.replace(CONTROL_RE, visible);
  return options?.lineBreaks ? out.replace(/\n/g, '\\n') : out;
}

/** A deep copy of `value` with every string passed through `escapeControlChars`. */
export function escapeControlCharsDeep<T>(value: T, options?: { lineBreaks?: boolean }): T {
  if (typeof value === 'string') return escapeControlChars(value, options) as T;
  if (Array.isArray(value)) return value.map(v => escapeControlCharsDeep(v, options)) as T;
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = escapeControlCharsDeep(v, options);
    return out as T;
  }
  return value;
}

// SGR colour sequences — the only escapes VASO's own output contains
// (scanned text is escaped above)
/**
 * Characters JSON.stringify leaves raw that still reorder or hide text when a
 * JSON or SARIF report is viewed (bidi controls and marks, zero-width and tag
 * characters, C1 controls such as U+009B CSI, DEL, line/paragraph separators).
 */
const JSON_UNSAFE_RE = /[\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\u2028\u2029\ufeff\u{e0000}-\u{e007f}]/gu;

/**
 * JSON text with those characters written as `\uXXXX` escapes: the parsed
 * values are unchanged (nothing is dropped), the file shows no live control
 * character. Only for the output of JSON.stringify, where such characters
 * can occur only inside strings.
 */
export function escapeJsonUnsafe(json: string): string {
  return json.replace(JSON_UNSAFE_RE, ch => ch.split('').map(u => `\\u${u.charCodeAt(0).toString(16).padStart(4, '0')}`).join(''));
}

const SGR_RE = /\u001b\[[0-9;]*m/g;

/**
 * A report as written to a file: no colour escapes. Terminal-format text is
 * rendered with chalk, which colours whenever stdout is a terminal — even
 * when the report goes to `-o report.txt`.
 */
export function stripColor(s: string): string {
  return s.replace(SGR_RE, '');
}

// XML 1.0 Char production: everything below 0x20 except tab, LF, CR is invalid,
// as are lone surrogates and U+FFFE/U+FFFF.
const XML_INVALID_RE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\ufffe\uffff]|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g;

/** Characters XML cannot carry at all, shown as `\xNN` so the document stays well-formed. */
export function stripXmlInvalid(s: string): string {
  return s.replace(XML_INVALID_RE, visible);
}
