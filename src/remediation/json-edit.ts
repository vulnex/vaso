/**
 * Edit one key of a JSON / JSONC / JSON5 document in its text, so a fix
 * keeps everything else byte-for-byte: comments, key order, number
 * spellings (`1e3`, `0x10`) and integers beyond 2^53 that a parse →
 * stringify round trip would round. Returns undefined when the document
 * isn't one this can follow; the caller then re-serializes.
 */

interface Member {
  key: string;
  keyStart: number;
  valueStart: number;
  valueEnd: number;
  container?: Container;
}

interface Container {
  kind: 'object' | 'array';
  start: number;
  /** Index of the closing bracket. */
  end: number;
  members: Member[];
}

class Fail extends Error {}

/** A JSON5 unquoted key: an ECMAScript IdentifierName (Unicode letters, `$`, `_`, `\uXXXX` escapes). */
const IDENTIFIER = /^(?:[\p{ID_Start}$_]|\\u[0-9a-fA-F]{4})(?:[\p{ID_Continue}$\u200c\u200d]|\\u[0-9a-fA-F]{4})*/u;

/** A JSON5-superset scanner that records where each value sits. */
class Scanner {
  i = 0;
  private depth = 0;
  constructor(private readonly s: string) {}

  ws(): void {
    for (;;) {
      const c = this.s[this.i];
      if (c === undefined) return;
      if (/[\s\u00a0\ufeff\u2028\u2029]/.test(c)) { this.i++; continue; }
      if (c === '/' && this.s[this.i + 1] === '/') {
        while (this.i < this.s.length && !'\n\r\u2028\u2029'.includes(this.s[this.i])) this.i++;
        continue;
      }
      if (c === '/' && this.s[this.i + 1] === '*') {
        const end = this.s.indexOf('*/', this.i + 2);
        if (end < 0) throw new Fail();
        this.i = end + 2;
        continue;
      }
      return;
    }
  }

  /** Scan a value at `i`; returns its container when it is an object or array. */
  value(): Container | undefined {
    if (++this.depth > 512) throw new Fail();
    try {
      const c = this.s[this.i];
      if (c === '{' || c === '[') return this.container(c === '{' ? 'object' : 'array');
      if (c === '"' || c === "'") { this.string(); return undefined; }
      const m = /^[^\s,\]}/]+/.exec(this.s.slice(this.i, this.i + 512));
      if (!m) throw new Fail();
      this.i += m[0].length;
      return undefined;
    } finally {
      this.depth--;
    }
  }

  /** Skip a quoted string; returns its decoded text (best effort for JSON5 escapes). */
  string(): string {
    const q = this.s[this.i];
    const start = this.i;
    let j = this.i + 1;
    while (j < this.s.length && this.s[j] !== q) j += this.s[j] === '\\' ? 2 : 1;
    if (j >= this.s.length) throw new Fail();
    this.i = j + 1;
    const body = this.s.slice(start + 1, j);
    try {
      return JSON.parse(`"${q === "'" ? body.replace(/\\'/g, "'").replace(/"/g, '\\"') : body}"`) as string;
    } catch {
      return body;
    }
  }

  private container(kind: 'object' | 'array'): Container {
    const close = kind === 'object' ? '}' : ']';
    const out: Container = { kind, start: this.i, end: -1, members: [] };
    this.i++;
    for (;;) {
      this.ws();
      if (this.s[this.i] === close) {
        out.end = this.i++;
        return out;
      }
      let key = String(out.members.length);
      const keyStart = this.i;
      if (kind === 'object') {
        if (this.s[this.i] === '"' || this.s[this.i] === "'") {
          key = this.string();
        } else {
          const m = IDENTIFIER.exec(this.s.slice(this.i, this.i + 256));
          if (!m) throw new Fail();
          key = m[0].replace(/\\u([0-9a-fA-F]{4})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)));
          this.i += m[0].length;
        }
        this.ws();
        if (this.s[this.i] !== ':') throw new Fail();
        this.i++;
        this.ws();
      }
      const valueStart = this.i;
      const container = this.value();
      out.members.push({ key, keyStart, valueStart, valueEnd: this.i, container });
      this.ws();
      if (this.s[this.i] === ',') { this.i++; continue; }
      if (this.s[this.i] === close) continue;
      throw new Fail();
    }
  }
}

function lineIndent(text: string, at: number): string {
  const lineStart = text.lastIndexOf('\n', at - 1) + 1;
  return /^[ \t]*/.exec(text.slice(lineStart))![0];
}

/** `value` as JSON whose continuation lines sit under `indent`, ending lines with `eol`. */
function render(value: unknown, unit: string, indent: string, eol: string): string {
  return JSON.stringify(value, null, unit).replace(/\n/g, `${eol}${indent}`);
}

/** The indentation unit the file uses (two spaces when it has none). */
function indentUnit(text: string): string {
  return /^[ \t]+(?=\S)/m.exec(text)?.[0] ?? '  ';
}

function nest(segments: string[], value: unknown): unknown {
  return segments.reduceRight<unknown>((v, k) => ({ [k]: v }), value);
}

/**
 * Set `segments` to `value` in `text`. The last member of a repeated key is
 * the one parsers keep, so that is the one edited.
 */
export function editJsonText(text: string, segments: string[], value: unknown): string | undefined {
  if (segments.length === 0) return undefined;
  const bom = text.startsWith('\ufeff') ? '\ufeff' : '';
  const body = bom ? text.slice(1) : text;
  let root: Container | undefined;
  try {
    const sc = new Scanner(body);
    sc.ws();
    root = sc.value();
    sc.ws();
    if (sc.i < body.length) return undefined;
  } catch (err) {
    if (err instanceof Fail) return undefined;
    throw err;
  }
  if (!root || root.kind !== 'object') return undefined;
  const unit = indentUnit(body);
  // Inserted lines end like the file's own (CRLF files stay CRLF)
  const eol = body.includes('\r\n') ? '\r\n' : '\n';

  let obj = root;
  for (let k = 0; k < segments.length; k++) {
    const member = [...obj.members].reverse().find(m => m.key === segments[k]);
    const last = k === segments.length - 1;
    if (member && !last && member.container?.kind === 'object') {
      obj = member.container;
      continue;
    }
    if (member) {
      // Final key, or an intermediate key that isn't an object: replace its value.
      const indent = lineIndent(body, member.keyStart);
      const replacement = render(last ? value : nest(segments.slice(k + 1), value), unit, indent, eol);
      return bom + body.slice(0, member.valueStart) + replacement + body.slice(member.valueEnd);
    }
    return bom + insertMember(body, obj, segments[k], nest(segments.slice(k + 1), value), unit, eol);
  }
  return undefined;
}

function insertMember(body: string, obj: Container, key: string, value: unknown, unit: string, eol: string): string {
  const prev = obj.members[obj.members.length - 1];
  if (!prev) {
    const outer = lineIndent(body, obj.start);
    const inner = outer + unit;
    return `${body.slice(0, obj.start)}{${eol}${inner}${JSON.stringify(key)}: ${render(value, unit, inner, eol)}${eol}${outer}}${body.slice(obj.end + 1)}`;
  }
  if (!body.slice(obj.start, obj.end).includes('\n')) {
    // A one-line object: `{ "a": 1 }` → `{ "a": 1, "b": 2 }`
    return `${body.slice(0, prev.valueEnd)}, ${JSON.stringify(key)}: ${render(value, unit, '', eol)}${body.slice(prev.valueEnd)}`;
  }
  const indent = lineIndent(body, prev.keyStart);
  const entry = `${JSON.stringify(key)}: ${render(value, unit, indent, eol)}`;
  // After the previous member's line, so a trailing `// comment` stays with it.
  const at = prev.valueEnd;
  const rest = /^[ \t]*(,)?[ \t]*(\/\/[^\r\n]*)?(?=\r?\n)/.exec(body.slice(at));
  if (rest && at + rest[0].length < obj.end) {
    const comma = rest[1] ? '' : ',';
    const lineEnd = at + rest[0].length;
    return `${body.slice(0, at)}${comma}${body.slice(at, lineEnd)}${eol}${indent}${entry}${rest[1] ? ',' : ''}${body.slice(lineEnd)}`;
  }
  return `${body.slice(0, at)},${eol}${indent}${entry}${body.slice(at)}`;
}
