/**
 * Same-file string constants folded into the statements that use them, for
 * the regex-based URL checks: `const AUTH_HOST = "http://auth.example.com"`
 * then `AUTH_HOST + "/authorize"`, `` `${AUTH_HOST}/authorize` ``,
 * `new URL("/oauth/token", AUTH_HOST)` or `urljoin(AUTH_HOST, "/token")` read
 * as the URL they build. A name bound to two different values is left alone.
 */

/** `const|let|var NAME = "…"` (JS) and module-level `NAME = "…"` (Python): a plain literal, no interpolation. */
const JS_BINDING = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*string\s*)?=\s*(["'`])([^"'`$\\\n]*)\2/g;
const PY_BINDING = /^([A-Za-z_]\w*)\s*(?::\s*str\s*)?=\s*[rRuU]?(["'])([^"'\\\n]*)\2\s*(?:#.*)?$/gm;

/** A plain string value: a URL or a path fragment worth folding. */
const FOLDABLE = /^(?:[a-zA-Z][\w+.-]*:\/\/[^\s]*|\/[\w\-./~%]*)$/;

export interface StringConstants {
  /** Names bound to exactly one foldable literal. */
  values: Map<string, string>;
  /** Matches any of those names as an identifier; undefined when there are none. */
  names?: RegExp;
}

export function stringConstants(code: string, opts: { python?: boolean } = {}): StringConstants {
  const seen = new Map<string, string | null>();
  const bind = (name: string, value: string): void => {
    const prev = seen.get(name);
    if (prev === undefined) seen.set(name, FOLDABLE.test(value) ? value : null);
    else if (prev !== value) seen.set(name, null);
  };
  for (const m of code.matchAll(JS_BINDING)) bind(m[1], m[3]);
  if (opts.python) for (const m of code.matchAll(PY_BINDING)) bind(m[1], m[3]);
  const values = new Map<string, string>();
  for (const [name, value] of seen) if (value !== null) values.set(name, value);
  if (values.size === 0) return { values };
  const alternatives = [...values.keys()].sort((a, b) => b.length - a.length).map((n) => n.replace(/\$/g, '\\$'));
  return { values, names: new RegExp(String.raw`(?<![\w$.])(?:${alternatives.join('|')})(?![\w$])`) };
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
    if (/^\s*(?::[^=]*)?=(?!=)/.test(whole.slice(offset + m.length))) return m;
    return `"${quoteSafe(values.get(m)!)}"`;
  });
  if (out === text) return undefined;
  // "a" + "b" → "ab" (any quote kind on either side)
  for (let guard = 0; guard < 20; guard++) {
    const next = out.replace(/(["'`])([^"'`\n]*)\1\s*\+\s*(["'`])([^"'`\n]*)\3/, (_m, _q1, a: string, _q2, b: string) => `"${a}${b}"`);
    if (next === out) break;
    out = next;
  }
  // new URL("/path", "http://host"), urljoin("http://host", "/path")
  out = out.replace(/\bnew\s+URL\s*\(\s*(["'`])([^"'`\n]*)\1\s*,\s*(["'`])([^"'`\n]*)\3\s*\)/g,
    (m, _q1, path: string, _q2, base: string) => { const url = resolveUrl(path, base); return url ? `"${quoteSafe(url)}"` : m; });
  out = out.replace(/\burljoin\s*\(\s*(["'])([^"'\n]*)\1\s*,\s*(["'])([^"'\n]*)\3\s*\)/g,
    (m, _q1, base: string, _q2, path: string) => { const url = resolveUrl(path, base); return url ? `"${quoteSafe(url)}"` : m; });
  return out;
}
