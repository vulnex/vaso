import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { decodeFsName, encodeFsPath, hasEscapedBytes } from './fs-names.js';

// dt25 g9-F4: names that aren't UTF-8 are held without loss, the same way
// locally (decodeFsName) and in the probe's JSON (probe/fs_names.go) — the
// corpus is shared with the Go test (TestFsNameEscapesMatchTS).
const corpus = JSON.parse(readFileSync(join(__dirname, '../../probe/testdata/fs-name-escapes.json'), 'utf-8')) as
  Array<{ name: string; hex: string; json: string }>;

describe('fs-names', () => {
  for (const c of corpus) {
    it(`${c.name}: decodes as the probe writes it, and encodes back to the same bytes`, () => {
      const bytes = Buffer.from(c.hex, 'hex');
      const decoded = decodeFsName(bytes);
      expect(decoded).toBe(JSON.parse(c.json));
      const back = encodeFsPath(decoded);
      if (bytes.toString('utf-8') === decoded) {
        expect(back).toBeUndefined();
      } else {
        expect(back?.toString('hex')).toBe(c.hex);
      }
    });
  }

  it('two names U+FFFD made one stay two', () => {
    expect(decodeFsName(Buffer.from([0xfe]))).not.toBe(decodeFsName(Buffer.from([0xff])));
  });

  it('a surrogate pair (an astral character) is not an escaped byte', () => {
    expect(hasEscapedBytes('😀')).toBe(false);
    expect(hasEscapedBytes('a\udcfe')).toBe(true);
    expect(encodeFsPath('/x/😀/\udcfe')?.equals(Buffer.concat([Buffer.from('/x/😀/'), Buffer.from([0xfe])]))).toBe(true);
  });
});
