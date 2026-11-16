/**
 * A package.json script (`"start": "cross-env X=1 node dist/index.js && …"`)
 * read the way a POSIX shell splits it: commands at unquoted `&&`, `||`,
 * `|`, `;`, `&` and newlines, words at unquoted whitespace, quotes removed.
 * One left-to-right pass each — a script is untrusted input (a regex with
 * `\s*` around the separators rescanned a long space run at every position).
 */

/** Longest script followed; a longer one is reported as not analysed. */
export const MAX_SCRIPT_CHARS = 8 * 1024;

/** The commands of a script line, trimmed, in order (empty ones dropped). */
export function scriptCommands(line: string): string[] {
  const out: string[] = [];
  let start = 0;
  let quote = '';
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      // `\'` stays inside `$'…'`
      if (c === '\\' && (quote === '"' || quote === '$')) i++;
      else if (c === "'" && quote === '$' || c === quote) quote = '';
      continue;
    }
    if (c === '\\') { i++; continue; }
    if (c === '$' && line[i + 1] === "'") { quote = '$'; i++; continue; }
    if (c === '"' || c === "'") { quote = c; continue; }
    if (c === ';' || c === '\n' || c === '&' || c === '|') {
      out.push(line.slice(start, i));
      if ((c === '&' || c === '|') && line[i + 1] === c) i++;
      start = i + 1;
    }
  }
  out.push(line.slice(start));
  return out.map((s) => s.trim()).filter((s) => s !== '');
}

/** Backslash escapes inside `$'…'` (bash ANSI-C quoting). */
const ANSI_C_ESCAPES: Record<string, string> = { a: '\x07', b: '\b', e: '\x1b', E: '\x1b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v', '\\': '\\', "'": "'", '"': '"', '?': '?' };

/** The escape at `command[at]` (just after the backslash) in `$'…'`: its text and length. */
function ansiCEscape(command: string, at: number): [string, number] {
  const c = command[at];
  if (c in ANSI_C_ESCAPES) return [ANSI_C_ESCAPES[c], 1];
  const hex = /^x([0-9A-Fa-f]{1,2})/.exec(command.slice(at, at + 3));
  if (hex) return [String.fromCharCode(parseInt(hex[1], 16)), hex[0].length];
  const oct = /^[0-7]{1,3}/.exec(command.slice(at, at + 3));
  if (oct) return [String.fromCharCode(parseInt(oct[0], 8) & 0xff), oct[0].length];
  return [`\\${c}`, 1];
}

/**
 * The words of one command, quotes removed (`sh -c 'node a.js'` → `sh`,
 * `-c`, `node a.js`); `$'…'` is read the way bash does, its escapes decoded.
 */
export function shellWords(command: string): string[] {
  const words: string[] = [];
  let word = '';
  let inWord = false;
  let quote = '';
  for (let i = 0; i < command.length; i++) {
    const c = command[i];
    if (quote === '$') {
      if (c === "'") quote = '';
      else if (c === '\\' && i + 1 < command.length) {
        const [text, n] = ansiCEscape(command, i + 1);
        word += text;
        i += n;
      } else word += c;
      continue;
    }
    if (quote) {
      if (c === quote) quote = '';
      else if (c === '\\' && quote === '"' && i + 1 < command.length && /["\\$`]/.test(command[i + 1])) word += command[++i];
      else word += c;
      continue;
    }
    if (c === '$' && command[i + 1] === "'") { quote = '$'; inWord = true; i++; continue; }
    if (c === '"' || c === "'") { quote = c; inWord = true; continue; }
    if (c === '\\' && i + 1 < command.length) { word += command[++i]; inWord = true; continue; }
    if (/\s/.test(c)) {
      if (inWord) words.push(word);
      word = '';
      inWord = false;
      continue;
    }
    word += c;
    inWord = true;
  }
  if (inWord) words.push(word);
  return words;
}

/**
 * The program and arguments a command runs, past `VAR=value` prefixes and
 * environment wrappers (`cross-env`, `env [-i] [-u NAME]`, `dotenv [-e f] --`).
 */
export function commandWords(command: string): string[] {
  const words = shellWords(command);
  let i = 0;
  for (;;) {
    while (i < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[i])) i++;
    const w = words[i];
    if (w === 'cross-env' || w === 'cross-env-shell') { i++; continue; }
    if (w === 'env') {
      i++;
      while (i < words.length && words[i].startsWith('-')) i += words[i] === '-u' || words[i] === '-C' || words[i] === '-S' ? 2 : 1;
      continue;
    }
    if (w === 'dotenv' || w === 'dotenvx') {
      i++;
      if (w === 'dotenvx' && words[i] === 'run') i++;
      while (i < words.length && words[i] !== '--' && words[i].startsWith('-')) i += /^-(?:e|v|c|f)$/.test(words[i]) ? 2 : 1;
      if (words[i] === '--') i++;
      continue;
    }
    break;
  }
  return words.slice(i);
}
