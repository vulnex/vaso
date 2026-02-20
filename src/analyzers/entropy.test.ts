import { describe, it, expect } from 'vitest';
import { shannonEntropy, findHighEntropyBlocks } from './entropy.js';

describe('Shannon Entropy', () => {
  it('returns 0 for empty string', () => {
    expect(shannonEntropy('')).toBe(0);
  });

  it('returns 0 for single-char string', () => {
    expect(shannonEntropy('aaaa')).toBe(0);
  });

  it('returns 1 for two equally distributed chars', () => {
    expect(shannonEntropy('ab')).toBeCloseTo(1, 1);
  });

  it('returns high entropy for random-looking string', () => {
    const base64 = 'SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IHN0cmluZw==';
    expect(shannonEntropy(base64)).toBeGreaterThan(4);
  });

  it('returns low entropy for repetitive string', () => {
    expect(shannonEntropy('aaabbbccc')).toBeLessThan(2);
  });
});

describe('findHighEntropyBlocks', () => {
  it('detects high-entropy strings', () => {
    // Generate a string with all printable ASCII to guarantee high entropy
    const highEntropy = Array.from({ length: 60 }, (_, i) => String.fromCharCode(33 + (i * 3) % 94)).join('');
    const code = `const payload = "${highEntropy}";`;
    const blocks = findHighEntropyBlocks(code);
    expect(blocks.length).toBeGreaterThan(0);
    expect(blocks[0].entropy).toBeGreaterThan(5);
  });

  it('ignores short strings', () => {
    const code = 'const x = "hello";';
    const blocks = findHighEntropyBlocks(code);
    expect(blocks).toHaveLength(0);
  });

  it('ignores comments', () => {
    const code = '// aGVsbG8gd29ybGQgdGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIHN0cmluZyB3aXRoIGhpZ2ggZW50cm9weQ==';
    const blocks = findHighEntropyBlocks(code);
    expect(blocks).toHaveLength(0);
  });
});
