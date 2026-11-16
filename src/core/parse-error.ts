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

const V8_JSON_SNIPPET = /,\s*(?:\.\.\.)?".*"(?:\.\.\.)?\s+is not valid JSON\s*$/s;

/** A parser error's message reduced to what went wrong and where — never the file's text. */
export function parseErrorMessage(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  // The description is the first line; yaml/smol-toml put the code frame after it
  let head = message.split(/\r?\n/, 1)[0].trim();
  if (V8_JSON_SNIPPET.test(head)) head = head.replace(V8_JSON_SNIPPET, ' (not valid JSON)');
  // yaml: "… at line 2, column 10:" introduces the frame
  head = head.replace(/:\s*$/, '');
  const e = err as { line?: unknown; column?: unknown; linePos?: unknown };
  if (!/\bline \d+/.test(head) && typeof e?.line === 'number') {
    head += typeof e.column === 'number' ? ` at line ${e.line}, column ${e.column}` : ` at line ${e.line}`;
  }
  return head;
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
