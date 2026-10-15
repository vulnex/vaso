/**
 * Text from scanned hosts (config values, file names, server names, the cwd
 * project name) is attacker-influenced. Written raw to a terminal, control
 * characters in it can clear the screen, forge hyperlinks (OSC 8) or retitle
 * the window; in XML some of them make the document invalid.
 */

// C0 controls except tab and newline, DEL, and C1 controls (0x80–0x9f; 0x9b is CSI)
const CONTROL_RE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g;

function visible(ch: string): string {
  const code = ch.charCodeAt(0);
  return code > 0xff ? `\\u${code.toString(16).padStart(4, '0')}` : `\\x${code.toString(16).padStart(2, '0')}`;
}

/** Line breaks: a server name or rule containing one forges a report line. */
const LINE_BREAK_RE = /[\n\u2028\u2029]/g;

/**
 * Control characters shown as `\xNN`. Newlines are kept unless
 * `lineBreaks` is set, which shows them as `\n` (or `\u2028`/`\u2029`) —
 * for single-line fields in terminal output.
 */
export function escapeControlChars(s: string, options?: { lineBreaks?: boolean }): string {
  const out = s.replace(CONTROL_RE, visible);
  return options?.lineBreaks ? out.replace(LINE_BREAK_RE, ch => (ch === '\n' ? '\\n' : visible(ch))) : out;
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

// XML 1.0 Char production: everything below 0x20 except tab, LF, CR is invalid,
// as are lone surrogates and U+FFFE/U+FFFF.
const XML_INVALID_RE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f￾￿]|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g;

/** Characters XML cannot carry at all, shown as `\xNN` so the document stays well-formed. */
export function stripXmlInvalid(s: string): string {
  return s.replace(XML_INVALID_RE, visible);
}
