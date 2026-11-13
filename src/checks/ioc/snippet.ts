import { snippetAround } from '../../core/patterns.js';
import { maskCredentialsInLine } from '../../reporting/serialize.js';

/** Characters masked on each side of the match. */
const MASK_REGION = 2048;

/**
 * The part of `line` around the IOC `re` matches, credentials masked FIRST:
 * a window cut from the raw line can start at a secret's value — after its
 * name, `user:` or `-u` — and the report masker then no longer recognises it.
 * Masking the whole line keeps every value masked, then the match is found
 * again in the masked text.
 */
export function iocSnippet(line: string, re: RegExp): string {
  // Only the part around the match is masked: the window is ~120 chars, and
  // masking a whole 5 MiB minified line per match cost seconds to minutes
  const raw = re.exec(line);
  const at = raw?.index ?? 0;
  let start = Math.max(0, at - MASK_REGION);
  // begin the region at a separator, not inside a value
  if (start > 0) {
    const ws = line.slice(start, at).search(/[\s,;{}]/);
    start = ws >= 0 ? start + ws + 1 : at;
  }
  const region = line.slice(start, Math.min(line.length, at + (raw?.[0].length ?? 0) + MASK_REGION));
  const masked = maskCredentialsInLine(region);
  const m = re.exec(masked);
  const out = m ? snippetAround(masked, m.index, m[0].length) : snippetAround(masked, 0, 0);
  // the region was cut from a longer line: say so even when the window starts at its edge
  return start > 0 && !out.startsWith('... ') ? `... ${out}` : out;
}
