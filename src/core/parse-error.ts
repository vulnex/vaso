/**
 * Parse-error messages without config content.
 *
 * The parsers VASO uses quote the file around a syntax error: `yaml` and
 * `smol-toml` append a code frame of the surrounding lines, V8's JSON.parse
 * quotes a few characters of the text (`Unexpected token 's', "sk-proj-…"…
 * is not valid JSON`). A config's neighbouring lines are often its
 * credentials, and these messages end up in CONFIG-LOAD findings, `vaso mcp`
 * output, fix failures and rule-file errors. Only the location is kept:
 * the parser's own description plus line and column.
 */

/**
 * What a parser reported, reduced to a description VASO knows (one of the
 * parser's fixed texts, nothing interpolated from the file) plus where.
 * yaml interpolates source text into several descriptions ("Block scalar
 * header includes extra characters: <rest of line>", "Unresolved tag: <tag>")
 * and V8 quotes up to a few lines around a JSON error (and the offending
 * character); a value written unquoted or after `>` is then printed whole.
 */
const V8_JSON_DESCRIPTIONS: RegExp[] = [
  /^Unexpected end of JSON input/,
  /^Expected property name or '\}' in JSON/,
  /^Expected ',' or '\}' after property value in JSON/,
  /^Expected ',' or '\]' after array element in JSON/,
  /^Expected double-quoted property name in JSON/,
  /^Expected ':' after property name in JSON/,
  /^Unexpected non-whitespace character after JSON/,
  /^Bad control character in string literal in JSON/,
  /^Bad escaped character in JSON/,
  /^Bad Unicode escape in JSON/,
  /^Unterminated string in JSON/,
  /^Exponent part is missing a number in JSON/,
  /^No number after minus sign in JSON/,
  /^Unterminated fractional number in JSON/,
];

/** What may follow a known V8 description in a scrubbed message: its position only. */
const V8_OWN_TAIL = /^(?: at position \d+(?: \(line \d+ column \d+\))?)?$/;

/** `at position N (line L column C)` from a V8 JSON message. */
const V8_POSITION = /\bin JSON at position (\d+)(?: \(line (\d+) column (\d+)\))?/;

/** smol-toml's descriptions are fixed texts (letters, spaces and a colon or two). */
const TOML_DESCRIPTION = /^Invalid TOML document: ([a-z0-9 ,.:-]+?)\s*(?:\r?\n|$)/i;

/** The JSON5 fallback's own (fixed) messages; `Unexpected 'x'` names a character of the file. */
const JSON5_MESSAGE = /^JSON5: (.+?) at line (\d+)$/;

/**
 * Forms this module produces, recognised again when a scrubbed message
 * passes through once more — alone, or followed by what VASO adds after
 * ` — ` (a Hermes release's reading of a duplicate key).
 */
const OWN_FORMS = [
  /^YAML syntax error \([a-z0-9 ]+\)(?: at line \d+, column \d+)?$/,
  /^YAML contains a self-referencing alias$/,
  /^found duplicate key(?: at line \d+)?$/,
  /^Invalid TOML document: [a-z0-9 ,.:-]+ at line \d+, column \d+$/,
  /^not valid JSON(?: at position \d+(?: \(line \d+ column \d+\))?)?$/,
  /^Unexpected end of JSON input$/,
  /^JSON5: [A-Za-z ,:'}\]\\]+ at line \d+$/,
];

/** A parser error's message reduced to what went wrong and where — never the file's text. */
export function parseErrorMessage(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  const e = err as { name?: unknown; code?: unknown; line?: unknown; column?: unknown; linePos?: unknown } | null;
  const where = (line: unknown, column: unknown) =>
    typeof line === 'number' ? (typeof column === 'number' ? ` at line ${line}, column ${column}` : ` at line ${line}`) : '';

  // yaml (YAMLParseError, YAMLWarning): the code and position, never the description
  if (e && typeof e === 'object' && typeof e.code === 'string' && /^[A-Z0-9_]+$/.test(e.code)
    && (Array.isArray(e.linePos) || /^YAML/.test(String(e.name)))) {
    const pos = Array.isArray(e.linePos) ? (e.linePos[0] as { line?: unknown; col?: unknown } | undefined) : undefined;
    return `YAML syntax error (${e.code.toLowerCase().replace(/_/g, ' ')})${where(pos?.line, pos?.col)}`;
  }
  const trimmed = message.trim();
  const sep = trimmed.indexOf(' — ');
  const head = sep < 0 ? trimmed : trimmed.slice(0, sep);
  if (OWN_FORMS.some(re => re.test(head)) || V8_JSON_DESCRIPTIONS.some(re => re.test(head) && V8_OWN_TAIL.test(head.replace(re, '')))) {
    return sep < 0 ? head : head + trimmed.slice(sep).split(/\r?\n/, 1)[0];
  }

  // V8 JSON.parse: a known description plus its position; anything else that
  // mentions JSON validity (`Unexpected token 'x', "…" is not valid JSON`,
  // the snippet over several lines) only says so
  if (/\bJSON\b/.test(message)) {
    const pos = V8_POSITION.exec(message);
    const at = pos ? ` at position ${pos[1]}${pos[2] ? ` (line ${pos[2]} column ${pos[3]})` : ''}` : '';
    const known = V8_JSON_DESCRIPTIONS.find(re => re.test(trimmed));
    if (known) {
      const description = trimmed.match(known)![0];
      return description + at;
    }
    if (/is not valid JSON|^Unexpected (?:token|number|string|identifier)\b/s.test(trimmed)) return `not valid JSON${at}`;
  }

  // yaml's errors raised while resolving the document (no code): the kind only
  if (/^Unresolved alias\b/.test(trimmed)) return 'YAML syntax error (unresolved alias)';

  // smol-toml: its fixed description and the position it carries
  const toml = TOML_DESCRIPTION.exec(message);
  if (toml) {
    const head = `Invalid TOML document: ${toml[1]}`;
    return /\bline \d+/.test(head) ? head : head + where(e?.line, e?.column);
  }

  // The JSON5 fallback
  const json5 = JSON5_MESSAGE.exec(trimmed);
  if (json5) return `JSON5: ${json5[1].replace(/^Unexpected '.*'$/s, 'Unexpected character')} at line ${json5[2]}`;

  // A duplicate-key message naming the key (yaml's omap check): the line is enough
  const dup = /^(?:found )?duplicate keys?\b(?:.*? at line (\d+))?/s.exec(trimmed);
  if (dup) return `found duplicate key${dup[1] ? ` at line ${dup[1]}` : ''}`;

  // A yaml description reaching here as plain text (no code): its known
  // shape, without what it quotes
  const yamlText = /^(.*?) at line (\d+), column (\d+)(?::|$)/s.exec(trimmed);
  if (yamlText && looksLikeYaml(yamlText[1])) return `YAML syntax error${where(Number(yamlText[2]), Number(yamlText[3]))}`;

  // Anything else (EACCES, ENOENT, a thrown description of VASO's own):
  // its first line
  return trimmed.split(/\r?\n/, 1)[0].trim().replace(/:\s*$/, '');
}

/** yaml's descriptions (errors.ts / compose / parse): the start of each. */
function looksLikeYaml(description: string): boolean {
  return /^(?:Block scalar|Unresolved tag|Anchors and tags|Implicit (?:map )?keys?|Nested mappings|Map keys|Missing closing|Unexpected (?:scalar|flow|end|.* in flow)|All (?:mapping|sequence|collection) items|Plain value|Tags and anchors|Comment|Tabs are|Invalid escape|Sequence items|Source contains|Aliases|Excessive alias|Unexpected token|duplicate keys?|Map keys must be unique|A block sequence|Flow (?:map|sequence)|Unresolved alias|Directive|Unsupported|Insufficient indentation|Missing (?:directives|,|:)|Block collections|Keys with collection|Document)/i.test(description);
}

/**
 * Rewrite a thrown parser error in place so its message (and any property
 * that quotes the file, smol-toml's `codeblock`) carries no content. The
 * error keeps its class, so callers that test for it are unaffected.
 */
export function scrubParseError<T>(err: T): T {
  if (!(err instanceof Error)) return err;
  const original = err.message;
  const message = parseErrorMessage(err);
  if (message === original && !('codeblock' in err)) return err;
  // V8 formats the stack lazily: read it before the message changes
  const stack = err.stack;
  try {
    Object.defineProperty(err, 'message', { value: message, writable: true, configurable: true, enumerable: false });
  } catch {
    // a frozen error: callers still go through parseErrorMessage
  }
  const props = err as unknown as Record<string, unknown>;
  if ('codeblock' in props) {
    try {
      delete props.codeblock;
    } catch {
      // non-configurable: leave it
    }
  }
  // The stack starts with the original message, frame included
  if (typeof stack === 'string') {
    const i = stack.indexOf(original);
    const frames = i >= 0 ? stack.slice(i + original.length) : '';
    try {
      err.stack = `${err.name}: ${message}${frames}`;
    } catch {
      // read-only stack
    }
  }
  return err;
}
