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

/** Control characters shown as `\xNN`; newlines kept. */
export function escapeControlChars(s: string): string {
  return s.replace(CONTROL_RE, visible);
}

/** A deep copy of `value` with every string passed through `escapeControlChars`. */
export function escapeControlCharsDeep<T>(value: T): T {
  if (typeof value === 'string') return escapeControlChars(value) as T;
  if (Array.isArray(value)) return value.map(v => escapeControlCharsDeep(v)) as T;
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = escapeControlCharsDeep(v);
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
