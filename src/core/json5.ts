/**
 * JSON5 parser (https://spec.json5.org) — OpenClaw's `openclaw.json` is JSON5:
 * comments, trailing commas, unquoted (identifier) keys, single-quoted and
 * line-continued strings, hex / signed / leading-dot numbers, Infinity, NaN.
 * Only used after strict JSON and JSONC have failed.
 */
export function parseJson5(text: string): unknown {
  return new Json5Parser(text.replace(/^\ufeff/, '')).parseDocument();
}

class Json5Parser {
  private i = 0;
  private depth = 0;

  constructor(private readonly s: string) {}

  parseDocument(): unknown {
    this.ws();
    const v = this.value();
    this.ws();
    if (this.i < this.s.length) this.fail('Unexpected trailing content');
    return v;
  }

  private fail(msg: string): never {
    const line = this.s.slice(0, this.i).split('\n').length;
    throw new SyntaxError(`JSON5: ${msg} at line ${line}`);
  }

  private ws(): void {
    for (;;) {
      const c = this.s[this.i];
      if (c === undefined) return;
      if (/[\s\u00a0\ufeff\u2028\u2029]/.test(c)) { this.i++; continue; }
      if (c === '/' && this.s[this.i + 1] === '/') {
        while (this.i < this.s.length && this.s[this.i] !== '\n') this.i++;
        continue;
      }
      if (c === '/' && this.s[this.i + 1] === '*') {
        const end = this.s.indexOf('*/', this.i + 2);
        if (end < 0) this.fail('Unterminated comment');
        this.i = end + 2;
        continue;
      }
      return;
    }
  }

  private value(): unknown {
    const c = this.s[this.i];
    if (c === '{') return this.object();
    if (c === '[') return this.array();
    if (c === '"' || c === "'") return this.string();
    if (c !== undefined && /[-+.\d]/.test(c)) return this.number();
    const word = /^[A-Za-z_$][\w$]*/.exec(this.s.slice(this.i, this.i + 32))?.[0];
    switch (word) {
      case 'true': this.i += 4; return true;
      case 'false': this.i += 5; return false;
      case 'null': this.i += 4; return null;
      case 'Infinity': this.i += 8; return Infinity;
      case 'NaN': this.i += 3; return NaN;
    }
    return this.fail(`Unexpected ${c === undefined ? 'end of input' : `'${c}'`}`);
  }

  private nest(): void {
    if (++this.depth > 512) this.fail('Nesting too deep');
  }

  private object(): Record<string, unknown> {
    this.nest();
    this.i++; // {
    const out: Record<string, unknown> = {};
    this.ws();
    while (this.s[this.i] !== '}') {
      const key = this.key();
      this.ws();
      if (this.s[this.i] !== ':') this.fail("Expected ':'");
      this.i++;
      this.ws();
      // defineProperty: a "__proto__" key is data, not the prototype
      Object.defineProperty(out, key, { value: this.value(), enumerable: true, writable: true, configurable: true });
      this.ws();
      if (this.s[this.i] === ',') { this.i++; this.ws(); continue; }
      if (this.s[this.i] !== '}') this.fail("Expected ',' or '}'");
    }
    this.i++;
    this.depth--;
    return out;
  }

  private key(): string {
    const c = this.s[this.i];
    if (c === '"' || c === "'") return this.string();
    const m = /^(?:[A-Za-z_$]|\\u[0-9a-fA-F]{4}|[^\x00-\x7f])(?:[\w$]|\\u[0-9a-fA-F]{4}|[^\x00-\x7f\s])*/.exec(this.s.slice(this.i));
    if (!m) this.fail('Expected a key');
    this.i += m[0].length;
    return m[0].replace(/\\u([0-9a-fA-F]{4})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)));
  }

  private array(): unknown[] {
    this.nest();
    this.i++; // [
    const out: unknown[] = [];
    this.ws();
    while (this.s[this.i] !== ']') {
      out.push(this.value());
      this.ws();
      if (this.s[this.i] === ',') { this.i++; this.ws(); continue; }
      if (this.s[this.i] !== ']') this.fail("Expected ',' or ']'");
    }
    this.i++;
    this.depth--;
    return out;
  }

  private string(): string {
    const quote = this.s[this.i++];
    let out = '';
    for (;;) {
      const c = this.s[this.i++];
      if (c === undefined) this.fail('Unterminated string');
      if (c === quote) return out;
      if (c === '\n' || c === '\r') this.fail('Unescaped line break in string');
      if (c !== '\\') { out += c; continue; }
      const e = this.s[this.i++];
      switch (e) {
        case 'b': out += '\b'; break;
        case 'f': out += '\f'; break;
        case 'n': out += '\n'; break;
        case 'r': out += '\r'; break;
        case 't': out += '\t'; break;
        case 'v': out += '\v'; break;
        case '0': out += '\0'; break;
        case 'x': {
          const h = this.s.slice(this.i, this.i + 2);
          if (!/^[0-9a-fA-F]{2}$/.test(h)) this.fail('Bad \\x escape');
          out += String.fromCharCode(parseInt(h, 16)); this.i += 2; break;
        }
        case 'u': {
          const h = this.s.slice(this.i, this.i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(h)) this.fail('Bad \\u escape');
          out += String.fromCharCode(parseInt(h, 16)); this.i += 4; break;
        }
        case '\r': if (this.s[this.i] === '\n') this.i++; break; // line continuation
        case '\n': case '\u2028': case '\u2029': break;
        case undefined: this.fail('Unterminated string'); break;
        default: out += e;
      }
    }
  }

  private number(): number {
    const m = /^[-+]?(?:0[xX][0-9a-fA-F]+|Infinity|NaN|(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?)/.exec(this.s.slice(this.i, this.i + 400));
    if (!m) this.fail('Bad number');
    this.i += m[0].length;
    const sign = m[0][0] === '-' ? -1 : 1;
    const body = m[0].replace(/^[-+]/, '');
    if (body === 'Infinity') return sign * Infinity;
    if (body === 'NaN') return NaN;
    if (/^0[xX]/.test(body)) return sign * parseInt(body.slice(2), 16);
    return sign * Number(body);
  }
}
