import { describe, it, expect } from 'vitest';
import { shannonEntropy, findHighEntropyBlocks } from './entropy.js';

describe('Shannon Entropy', () => {
  it('returns 0 for empty string', () => {
    const e = shannonEntropy('');
    console.log(`[entropy] "" → ${e}`);
    expect(e).toBe(0);
  });

  it('returns 0 for single-char string', () => {
    const e = shannonEntropy('aaaa');
    console.log(`[entropy] "aaaa" → ${e}`);
    expect(e).toBe(0);
  });

  it('returns 1 for two equally distributed chars', () => {
    const e = shannonEntropy('ab');
    console.log(`[entropy] "ab" → ${e.toFixed(4)}`);
    expect(e).toBeCloseTo(1, 1);
  });

  it('returns high entropy for random-looking string', () => {
    const base64 = 'SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IHN0cmluZw==';
    const e = shannonEntropy(base64);
    console.log(`[entropy] base64 string (${base64.length} chars) → ${e.toFixed(4)}`);
    expect(e).toBeGreaterThan(4);
  });

  it('returns low entropy for repetitive string', () => {
    const e = shannonEntropy('aaabbbccc');
    console.log(`[entropy] "aaabbbccc" → ${e.toFixed(4)}`);
    expect(e).toBeLessThan(2);
  });
});

describe('findHighEntropyBlocks', () => {
  it('detects high-entropy strings', () => {
    const highEntropy = Array.from({ length: 60 }, (_, i) => String.fromCharCode(33 + (i * 3) % 94)).join('');
    const code = `const payload = "${highEntropy}";`;
    const blocks = findHighEntropyBlocks(code);
    console.log(`[entropy] high-entropy block → found ${blocks.length} block(s)`, blocks[0] ? JSON.stringify(blocks[0]) : '(none)');
    expect(blocks.length).toBeGreaterThan(0);
    expect(blocks[0].entropy).toBeGreaterThan(5);
  });

  it('ignores short strings', () => {
    const code = 'const x = "hello";';
    const blocks = findHighEntropyBlocks(code);
    console.log(`[entropy] short string "hello" → ${blocks.length} block(s) (ignored)`);
    expect(blocks).toHaveLength(0);
  });

  it('ignores comments', () => {
    const code = '// aGVsbG8gd29ybGQgdGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIHN0cmluZyB3aXRoIGhpZ2ggZW50cm9weQ==';
    const blocks = findHighEntropyBlocks(code);
    console.log(`[entropy] comment with base64 → ${blocks.length} block(s) (ignored)`);
    expect(blocks).toHaveLength(0);
  });
});

describe('findHighEntropyBlocks snippets', () => {
  it('never quotes the high-entropy string itself', () => {
    const secret = 'Zq8Lr2Vx9Kp4Ty7Wm1Nc6Hb3Jd5Gf0SaXe8Ru2Io4Pl7Mk9Qw1Ev3Bn6Cz0YtAhUgDfSj';
    const [block] = findHighEntropyBlocks(`TOKEN = "${secret}"`, 4.5, 40);
    expect(block).toBeDefined();
    expect(block.snippet).toBe(`<literal, ${secret.length} chars, high-entropy string>`);
    expect(block.snippet).not.toContain(secret.slice(0, 4));
    expect(block.snippet).not.toContain(secret.slice(-4));
    expect(block.snippet).not.toContain(secret.slice(0, 16));
    expect(block.snippet).not.toContain(secret.slice(-12));
  });
});
