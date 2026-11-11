import { describe, expect, it } from 'vitest';
import { maskCredentialsInLine, maskCredentialsInText } from './serialize.js';

describe('report masking — dt21: linear on adversarial runs', () => {
  it('stays fast on long runs of the new patterns', () => {
    for (const s of ['Ab-'.repeat(40_000), 'Ocp-Apim-'.repeat(15_000), '-p'.repeat(60_000), ' -k'.repeat(40_000), 'a.b='.repeat(30_000),
      '--apiToken'.repeat(12_000), 'gh'.repeat(60_000), '0x'.repeat(60_000), 'sk-'.repeat(40_000), `https://u:${'x'.repeat(100_000)}`,
      `Server "${'a'.repeat(100_000)}`, `${' '.repeat(100_000)}=`]) {
      const start = Date.now();
      maskCredentialsInLine(s);
      maskCredentialsInText(s);
      expect(Date.now() - start, s.slice(0, 12)).toBeLessThan(1500);
    }
  });
});
