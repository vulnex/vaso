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
      if (c === '\\' && quote === '"') i++;
      else if (c === quote) quote = '';
      continue;
    }
    if (c === '\\') { i++; continue; }
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

/** The words of one command, quotes removed (`sh -c 'node a.js'` → `sh`, `-c`, `node a.js`). */
export function shellWords(command: string): string[] {
  const words: string[] = [];
  let word = '';
  let inWord = false;
  let quote = '';
  for (let i = 0; i < command.length; i++) {
    const c = command[i];
    if (quote) {
      if (c === quote) quote = '';
      else if (c === '\\' && quote === '"' && i + 1 < command.length && /["\\$`]/.test(command[i + 1])) word += command[++i];
      else word += c;
      continue;
    }
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
