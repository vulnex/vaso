/**
 * Strip JSONC comments (// ..., /* ... *\/) and trailing commas from a string,
 * preserving string contents. Used by adapters whose configs are JSON-with-
 * comments (OpenCode, Gemini CLI, Qwen Code) — the shared config-loader only
 * handles strict JSON.
 */
export function stripJsonc(raw: string): string {
  let out = '';
  let i = 0;
  let inString = false;
  let stringQuote: '"' | "'" | undefined;
  while (i < raw.length) {
    const c = raw[i];
    const next = raw[i + 1];
    if (inString) {
      out += c;
      if (c === '\\' && i + 1 < raw.length) {
        out += raw[i + 1];
        i += 2;
        continue;
      }
      if (c === stringQuote) {
        inString = false;
        stringQuote = undefined;
      }
      i++;
      continue;
    }
    if (c === '"' || c === "'") {
      inString = true;
      stringQuote = c as '"' | "'";
      out += c;
      i++;
      continue;
    }
    if (c === '/' && next === '/') {
      while (i < raw.length && raw[i] !== '\n') i++;
      continue;
    }
    if (c === '/' && next === '*') {
      i += 2;
      while (i < raw.length && !(raw[i] === '*' && raw[i + 1] === '/')) i++;
      i += 2;
      continue;
    }
    out += c;
    i++;
  }
  return out.replace(/,(\s*[\]}])/g, '$1');
}
