import { parseJson5 } from './json5.js';
/**
 * Strip JSONC comments (// ..., /* ... *\/) and trailing commas from a string,
 * preserving string contents. Used by adapters whose configs are JSON-with-
 * comments (OpenCode, Gemini CLI, Qwen Code) — the shared config-loader only
 * handles strict JSON.
 */
export function stripJsonc(raw: string): string {
  raw = raw.replace(/^\uFEFF/, '');
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
      // A line comment ends at LF or CR (a CR-only file is one line otherwise)
      while (i < raw.length && raw[i] !== '\n' && raw[i] !== '\r') i++;
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

/**
 * Parse a `.json` config the way the agents themselves accept it: strict JSON,
 * then JSONC (VS Code-family settings: comments, trailing commas), then JSON5
 * (OpenClaw's openclaw.json: unquoted keys, single quotes, …). A real syntax
 * error reports the strict parser's message.
 */
export function parseJsonLenient(raw: string): unknown {
  try {
    return JSON.parse(raw);
  } catch (err) {
    try {
      return JSON.parse(stripJsonc(raw));
    } catch {
      try {
        return parseJson5(raw);
      } catch {
        throw err;
      }
    }
  }
}
