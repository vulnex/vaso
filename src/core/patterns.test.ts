import { describe, it, expect } from 'vitest';
import { redactSecret, redactSecretsInLine } from './patterns.js';

describe('redactSecret', () => {
  it('reveals first 4 + last 4 characters of long tokens', () => {
    const token = 'sk-ant-aaaaaaaaaaaaaaaaaaaabbbbcccc';
    expect(redactSecret(token)).toBe('sk-a...cccc');
  });

  it('fully masks short tokens with their length', () => {
    expect(redactSecret('short')).toBe('[REDACTED:5c]');
    expect(redactSecret('twelve_chars')).toBe('[REDACTED:12c]');
  });

  it('switches to fingerprint at 13 characters', () => {
    expect(redactSecret('thirteen_char')).toBe('thir...char');
  });
});

describe('redactSecretsInLine', () => {
  it('redacts a single API key while preserving surrounding context', () => {
    const line = '  "apiKey": "sk-abc123456789012345678901234567890123",';
    const out = redactSecretsInLine(line);
    expect(out).toContain('"apiKey":');
    expect(out).not.toContain('sk-abc123456789012345678901234567890123');
    expect(out).toMatch(/sk-a\.\.\./);
  });

  it('redacts every secret in a line, even when multiple distinct patterns match', () => {
    const line =
      '"openai": "sk-aaaaaaaaaaaaaaaaaaaaaaaa", "github": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"';
    const out = redactSecretsInLine(line);
    expect(out).not.toContain('sk-aaaaaaaaaaaaaaaaaaaaaaaa');
    expect(out).not.toContain('ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    expect(out).toContain('"openai"');
    expect(out).toContain('"github"');
  });

  it('redacts multiple occurrences of the same pattern in one line', () => {
    const line =
      '"a": "sk-aaaaaaaaaaaaaaaaaaaaaaaa", "b": "sk-bbbbbbbbbbbbbbbbbbbbbbbb"';
    const out = redactSecretsInLine(line);
    expect(out).not.toContain('aaaaaaaaaaaaaaaaaaaaaaaa');
    expect(out).not.toContain('bbbbbbbbbbbbbbbbbbbbbbbb');
  });

  it('truncates long lines after redaction with a trailing ellipsis', () => {
    const filler = 'x'.repeat(150);
    const out = redactSecretsInLine(filler, 80);
    expect(out.length).toBe(83);
    expect(out.endsWith('...')).toBe(true);
  });

  it('passes through lines with no secrets unchanged (modulo trim)', () => {
    expect(redactSecretsInLine('  "host": "127.0.0.1"  ')).toBe('"host": "127.0.0.1"');
  });
});
