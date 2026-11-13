import { isAbsolute, sep } from 'node:path';

/**
 * A `path.relative()` result that leads out of its base: `..`, `../x`, or an
 * absolute path (another drive). `..x.js` is a file inside the base, so a
 * bare `startsWith('..')` test is wrong.
 */
export function relEscapes(rel: string): boolean {
  return rel === '..' || rel.startsWith(`..${sep}`) || rel.startsWith('../') || isAbsolute(rel);
}
