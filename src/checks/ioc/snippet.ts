import { snippetAround } from '../../core/patterns.js';
import { maskCredentialsInLine } from '../../reporting/serialize.js';

let lastLine: string | undefined;
let lastMasked = '';

/**
 * The part of `line` around the IOC `re` matches, credentials masked FIRST:
 * a window cut from the raw line can start at a secret's value — after its
 * name, `user:` or `-u` — and the report masker then no longer recognises it.
 * Masking the whole line keeps every value masked, then the match is found
 * again in the masked text.
 */
export function iocSnippet(line: string, re: RegExp): string {
  // The whole line is masked (once per line — every IOC on a minified file's
  // one line asks for the same): a region cut around the match can start
  // inside a long value and drop the key that makes it a credential
  if (line !== lastLine) {
    lastLine = line;
    lastMasked = maskCredentialsInLine(line);
  }
  const masked = lastMasked;
  const m = re.exec(masked);
  return m ? snippetAround(masked, m.index, m[0].length) : snippetAround(masked, 0, 0);
}
