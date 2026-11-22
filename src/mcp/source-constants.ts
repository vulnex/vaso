/**
 * Same-file string constants folded into the statements that use them, for
 * the regex-based URL checks: `const AUTH_HOST = "http://auth.example.com"`
 * then `AUTH_HOST + "/authorize"`, `` `${AUTH_HOST}/authorize` ``,
 * `new URL("/oauth/token", AUTH_HOST)`, `urljoin(AUTH_HOST, "/token")`,
 * `"{}/token".format(AUTH_HOST)` or `"%s/token" % AUTH_HOST` read as the URL
 * they build. A name assigned more than once (reassigned, shadowed, a
 * parameter elsewhere) is left alone: which value reaches the use is unknown.
 */

/** `const|let|var NAME = "…"` (JS) and `NAME = "…"` (Python, at any indent; `: str` / `: Final` annotations): a plain literal, no interpolation. */
const JS_BINDING = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*string\s*)?=\s*(["'`])([^"'`$\\\n]*)\2/g;
const PY_ANNOTATION = String.raw`(?::\s*(?:str|(?:typing\.)?Final(?:\[\s*str\s*\])?)\s*)?`;
const PY_BINDING = new RegExp(String.raw`^[ \t]*([A-Za-z_]\w*)\s*${PY_ANNOTATION}=\s*[rRuU]?(["'])([^"'\\\n]*)\2\s*(?:#.*)?$`, 'gm');
/** A binding to an expression (`const BASE = HOST + "/oauth"`), folded once the constants it uses are known. */
const JS_EXPR_BINDING = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*string\s*)?=\s*([^;\n]+?)\s*;?[ \t]*$/gm;
const PY_EXPR_BINDING = new RegExp(String.raw`^[ \t]*([A-Za-z_]\w*)\s*${PY_ANNOTATION}=(?!=)\s*([^\n#]+?)\s*(?:#.*)?$`, 'gm');
/**
 * A literal default behind an environment lookup — the value used when the
 * variable is unset: `const AUTH = process.env.AUTH_URL ?? "http://…"` (also
 * `||`), Python `AUTH = os.environ.get("AUTH_URL", "http://…")` /
 * `os.getenv("AUTH_URL", "http://…")`.
 */
const JS_DEFAULT_BINDING = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*string\s*)?=\s*\(?\s*process\.env(?:\.[A-Za-z_$][\w$]*|\[\s*(["'])[^"'\n]*\2\s*\])\s*\)?\s*(?:\?\?|\|\|)\s*(["'`])([^"'`$\\\n]*)\3/g;
const PY_DEFAULT_BINDING = new RegExp(String.raw`^[ \t]*([A-Za-z_]\w*)\s*${PY_ANNOTATION}=\s*os\.(?:environ\.get|getenv)\(\s*(["'])[^"'\n]*\2\s*,\s*[rRuU]?(["'])([^"'\\\n]*)\3\s*\)\s*(?:#.*)?$`, 'gm');
/** `const NAME = {` — an object literal whose string properties are folded as `NAME.key`. */
const JS_OBJECT_BINDING = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*\{/g;
const OBJECT_PROPERTY = /(?:^|[,{])\s*(?:([A-Za-z_$][\w$]*)|(["'])([A-Za-z_$][\w$]*)\2)\s*:\s*(["'`])([^"'`$\\\n]*)\4\s*(?=,|\}|$)/gm;

/** Every assignment target: `NAME =`, `NAME +=`, `NAME ??=` (JS; not `==`, `=>`). */
const JS_ASSIGNED = /(?<![\w$.])([A-Za-z_$][\w$]*)\s*(?:[-+*/%]|\*\*|\|\||&&|\?\?|<<|>>>?|[&|^])?=(?![=>])/g;
/** Python: `NAME =` (any indent, annotated or not), `NAME +=`, `for NAME in`, `as NAME`, `NAME :=`. */
const PY_ASSIGNED = /^[ \t]*([A-Za-z_]\w*)\s*(?::[^=\n]+)?(?:[-+*/%@&|^]|\/\/|\*\*|<<|>>)?=(?!=)|\bfor\s+([A-Za-z_]\w*)\s+in\b|\bas\s+([A-Za-z_]\w*)|\b([A-Za-z_]\w*)\s*:=/gm;
const PY_PARAMS = /\bdef\s+\w+\s*\(([^)]*)\)/g;

/**
 * A plain string value worth folding: a URL, a path fragment, or a bare
 * web scheme (`const SCHEME = "http"` used as `${SCHEME}://host/…`).
 */
const FOLDABLE = /^(?:[a-zA-Z][\w+.-]*:\/\/[^\s]*|\/[\w\-./~%]*|(?:https?|wss?)(?::\/\/)?)$/i;
/**
 * Upper bound on rounds of folding constants built from constants
 * (`HOST` → `BASE = HOST + "/oauth"` → …). Folding stops earlier, at the
 * first round that adds nothing; a chain of any realistic length is followed.
 */
const MAX_DERIVED_ROUNDS = 64;
/** Characters of object literals read in one file when folding their properties. */
const OBJECT_SCAN_BUDGET = 4 * 1024 * 1024;

export interface StringConstants {
  /** Names bound to exactly one foldable literal. */
  values: Map<string, string>;
  /** Matches any of those names as an identifier; undefined when there are none. */
  names?: RegExp;
}

/** How many times each name is assigned (or bound as a parameter) in the file. */
function assignmentCounts(code: string, python: boolean): Map<string, number> {
  const counts = new Map<string, number>();
  const add = (name: string | undefined): void => { if (name) counts.set(name, (counts.get(name) ?? 0) + 1); };
  if (!python) {
    for (const m of code.matchAll(JS_ASSIGNED)) add(m[1]);
    return counts;
  }
  for (const m of code.matchAll(PY_ASSIGNED)) add(m[1] ?? m[2] ?? m[3] ?? m[4]);
  for (const m of code.matchAll(PY_PARAMS)) for (const p of m[1].split(',')) add(/^\s*\**([A-Za-z_]\w*)/.exec(p)?.[1]);
  return counts;
}

function withNames(values: Map<string, string>): StringConstants {
  if (values.size === 0) return { values };
  const alternatives = [...values.keys()].sort((a, b) => b.length - a.length).map((n) => n.replace(/[$.]/g, '\\$&'));
  return { values, names: new RegExp(String.raw`(?<![\w$.])(?:${alternatives.join('|')})(?![\w$])`) };
}

export function stringConstants(code: string, opts: { python?: boolean } = {}): StringConstants {
  const python = opts.python === true;
  const counts = assignmentCounts(code, python);
  // assigned once: by the binding itself
  const once = (name: string): boolean => (counts.get(name) ?? 0) <= 1;
  const seen = new Map<string, string | null>();
  const bind = (name: string, value: string): void => {
    const prev = seen.get(name);
    if (prev === undefined) seen.set(name, FOLDABLE.test(value) && once(name) ? value : null);
    else if (prev !== value) seen.set(name, null);
  };
  for (const m of code.matchAll(JS_BINDING)) bind(m[1], m[3]);
  if (python) for (const m of code.matchAll(PY_BINDING)) bind(m[1], m[3]);
  // a literal default behind an environment lookup
  if (!python) for (const m of code.matchAll(JS_DEFAULT_BINDING)) bind(m[1], m[4]);
  else for (const m of code.matchAll(PY_DEFAULT_BINDING)) bind(m[1], m[4]);
  // string properties of a once-bound object literal: `CFG.authHost`
  if (!python) {
    // bounded: each object is read to its close, at most OBJECT_SCAN_BUDGET chars in all
    let budget = OBJECT_SCAN_BUDGET;
    for (const m of code.matchAll(JS_OBJECT_BINDING)) {
      if (budget <= 0) break;
      if (!once(m[1])) continue;
      const body = objectBody(code, m.index + m[0].length, Math.min(budget, 65536));
      budget -= body.scanned;
      if (body.text === undefined) continue;
      for (const p of body.text.matchAll(OBJECT_PROPERTY)) {
        const key = p[1] ?? p[3];
        const qualified = `${m[1]}.${key}`;
        // the property written elsewhere: which value is read is unknown
        if (new RegExp(String.raw`(?<![\w$.])${m[1].replace(/\$/g, '\\$')}\s*(?:\.\s*${key.replace(/\$/g, '\\$')}|\[\s*["']${key.replace(/\$/g, '\\$')}["']\s*\])\s*(?:[-+*/%]|\?\?|\|\||&&)?=(?![=>])`).test(code)) {
          seen.set(qualified, null);
          continue;
        }
        bind(qualified, p[5]);
      }
    }
  }
  const values = new Map<string, string>();
  for (const [name, value] of seen) if (value !== null) values.set(name, value);
  // constants built from constants: `const BASE = HOST + "/oauth"`
  for (let round = 0; round < MAX_DERIVED_ROUNDS && values.size > 0; round++) {
    const known = withNames(values);
    let added = false;
    for (const m of code.matchAll(python ? PY_EXPR_BINDING : JS_EXPR_BINDING)) {
      const [, name, expr] = m;
      if (values.has(name) || seen.get(name) === null || !once(name)) continue;
      const folded = foldConstants(expr, known);
      const value = folded === undefined ? undefined : /^\s*"([^"\n]*)"\s*$/.exec(folded)?.[1];
      if (value !== undefined && FOLDABLE.test(value)) { values.set(name, value); added = true; }
    }
    if (!added) break;
  }
  return withNames(values);
}

/**
 * The top level of an object literal whose `{` ends just before `from`, with
 * nested objects/arrays blanked; undefined when it doesn't close within `limit` chars.
 */
function objectBody(code: string, from: number, limit: number): { text?: string; scanned: number } {
  let depth = 1;
  let quote = '';
  let out = '';
  const end = Math.min(code.length, from + limit);
  for (let i = from; i < end; i++) {
    const ch = code[i];
    if (quote) {
      if (ch === '\\') { if (depth === 1) out += ch + (code[i + 1] ?? ''); i++; continue; }
      if (ch === quote) quote = '';
      if (depth === 1) out += ch;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; if (depth === 1) out += ch; continue; }
    if (ch === '{' || ch === '[' || ch === '(') { depth++; continue; }
    if (ch === '}' || ch === ']' || ch === ')') {
      depth--;
      if (depth === 0) return { text: out, scanned: i - from + 1 };
      continue;
    }
    if (depth === 1) out += ch;
  }
  return { scanned: end - from };
}

/** A name followed by its assignment: the binding, not a use. */
const isBinding = (text: string, end: number): boolean => /^\s*(?::[^=]*)?=(?!=)/.test(text.slice(end));

/** The values of the constants `text` uses (a constant's own binding is no use of it). */
export function referencedConstants(text: string, constants: StringConstants): string[] {
  if (!constants.names) return [];
  const out = new Set<string>();
  for (const m of text.matchAll(new RegExp(constants.names.source, 'g'))) {
    if (!isBinding(text, m.index + m[0].length)) out.add(constants.values.get(m[0])!);
  }
  for (const m of text.matchAll(/\$?\{\s*([A-Za-z_$][\w$]*)\s*\}/g)) if (constants.values.has(m[1])) out.add(constants.values.get(m[1])!);
  return [...out];
}

/** `base` resolved against `path` as `new URL(path, base)` would, or undefined. */
function resolveUrl(path: string, base: string): string | undefined {
  try {
    return new URL(path, base).href;
  } catch {
    return undefined;
  }
}

/**
 * `text` with the constants it mentions written in as literals and the string
 * concatenations, templates and URL joins over them folded; undefined when
 * the statement uses none of them (or is one of their own bindings).
 */
export function foldConstants(text: string, constants: StringConstants): string | undefined {
  if (!constants.names || !constants.names.test(text)) return undefined;
  const { values } = constants;
  const quoteSafe = (v: string): string => v.replace(/"/g, '%22');
  let out = text;
  // `${NAME}` in a template, `{NAME}` in an f-string (not an object shorthand `{ NAME }`)
  const placeholder = /\bf["']/.test(text) ? /\$?\{\s*([A-Za-z_$][\w$]*)\s*\}/g : /\$\{\s*([A-Za-z_$][\w$]*)\s*\}/g;
  out = out.replace(placeholder, (m, name: string) => (values.has(name) ? values.get(name)! : m));
  // a bare reference — not the name's own binding
  out = out.replace(new RegExp(constants.names.source, 'g'), (m, offset: number, whole: string) => {
    if (isBinding(whole, offset + m.length)) return m;
    return `"${quoteSafe(values.get(m)!)}"`;
  });
  if (out === text) return undefined;
  // "{}/token".format("http://host"), "%s/token" % "http://host": one placeholder, one value
  out = out.replace(/(["'])([^"'\n]*)\1\s*\.format\(\s*(["'])([^"'\n]*)\3\s*\)/g, (m, _q1, tpl: string, _q2, v: string) =>
    (/^[^{}]*\{0?\}[^{}]*$/.test(tpl) ? `"${tpl.replace(/\{0?\}/, v)}"` : m));
  out = out.replace(/(["'])([^"'\n]*)\1\s*%\s*\(?\s*(["'])([^"'\n]*)\3\s*,?\s*\)?/g, (m, _q1, tpl: string, _q2, v: string) =>
    (/^[^%]*%s[^%]*$/.test(tpl) ? `"${tpl.replace('%s', v)}"` : m));
  // "a" + "b" → "ab" (any quote kind on either side)
  for (let guard = 0; guard < 20; guard++) {
    const next = out.replace(/(["'`])([^"'`\n]*)\1\s*\+\s*(["'`])([^"'`\n]*)\3/, (_m, _q1, a: string, _q2, b: string) => `"${a}${b}"`);
    if (next === out) break;
    out = next;
  }
  // ["http://host", "/authorize"].join("") — literals only, one literal separator
  out = out.replace(/\[\s*((?:(["'`])[^"'`\n]*\2\s*,\s*)*(["'`])[^"'`\n]*\3)\s*,?\s*\]\s*\.join\(\s*(?:(["'`])([^"'`\n]*)\4)?\s*\)/g,
    (_m, items: string, ...rest: unknown[]) => {
      const sep = typeof rest[3] === 'string' ? rest[3] as string : ',';
      const parts = [...items.matchAll(/(["'`])([^"'`\n]*)\1/g)].map((p) => p[2]);
      return `"${parts.join(sep)}"`;
    });
  // new URL("/path", "http://host"), urljoin("http://host", "/path")
  out = out.replace(/\bnew\s+URL\s*\(\s*(["'`])([^"'`\n]*)\1\s*,\s*(["'`])([^"'`\n]*)\3\s*\)/g,
    (m, _q1, path: string, _q2, base: string) => { const url = resolveUrl(path, base); return url ? `"${quoteSafe(url)}"` : m; });
  out = out.replace(/\burljoin\s*\(\s*(["'])([^"'\n]*)\1\s*,\s*(["'])([^"'\n]*)\3\s*\)/g,
    (m, _q1, base: string, _q2, path: string) => { const url = resolveUrl(path, base); return url ? `"${quoteSafe(url)}"` : m; });
  // new URL("http://host/authorize") (and its .href / .origin / .toString()) is that URL
  out = out.replace(/\bnew\s+URL\s*\(\s*(["'`])([^"'`\n]*)\1\s*\)(?:\s*\.\s*(href|origin|toString\s*\(\s*\)))?/g,
    (m, _q, url: string, part: string | undefined) => {
      let parsed: URL;
      try { parsed = new URL(url); } catch { return m; }
      return `"${quoteSafe(part === 'origin' ? parsed.origin : parsed.href)}"`;
    });
  // a URL built after that (`new URL(AUTH).origin + "/authorize"`)
  for (let guard = 0; guard < 20; guard++) {
    const next = out.replace(/(["'`])([^"'`\n]*)\1\s*\+\s*(["'`])([^"'`\n]*)\3/, (_m, _q1, a: string, _q2, b: string) => `"${a}${b}"`);
    if (next === out) break;
    out = next;
  }
  return out;
}
