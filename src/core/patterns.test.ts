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

  // ----- Tail-leak regressions for variable-length tokens -----
  //
  // Each test uses a token whose middle and tail bytes are visually distinct
  // so we can detect the bridging bytes that would leak when the regex stops
  // short of the real token end. With {N}-style quantifiers those bridging
  // bytes leaked into the redacted line; {N,} consumes them as part of the
  // match and they never appear in the output.

  it('redacts a longer-than-spec ghp_ token without leaking bridging bytes', () => {
    // 4 (ghp_) + 38 (mid 'A's) + 4 (tail 'WXYZ') = 46 chars. With the old
    // {36} quantifier, the regex stopped at ghp_ + 36 A's, leaving 'AAWXYZ'
    // (2 extra A's plus the distinctive tail) un-redacted in the line.
    const tok = 'ghp_' + 'A'.repeat(38) + 'WXYZ';
    const line = `"GITHUB_TOKEN": "${tok}"`;
    const out = redactSecretsInLine(line);
    expect(out).not.toContain(tok);
    expect(out).not.toContain('AAWXYZ');
    expect(out).toMatch(/ghp_\.\.\.WXYZ/);
  });

  it('redacts a longer-than-spec gho_ token without leaking bridging bytes', () => {
    const tok = 'gho_' + 'B'.repeat(40) + 'WXYZ';
    const line = `oauth_token=${tok};`;
    const out = redactSecretsInLine(line);
    expect(out).not.toContain(tok);
    expect(out).not.toContain('BBWXYZ');
    expect(out).toMatch(/gho_\.\.\.WXYZ/);
  });

  it('redacts a Telegram bot token longer than 35 chars after the colon', () => {
    // The previous /[0-9]{10}:[A-Za-z0-9_-]{35}\b/ failed to match when the
    // suffix exceeded 35 chars because \b couldn't anchor at a word boundary
    // mid-token, leaving the whole token unredacted.
    const tok = '1234567890:' + 'A'.repeat(38) + 'WXYZ';
    const line = `TELEGRAM_BOT_TOKEN=${tok}`;
    const out = redactSecretsInLine(line);
    expect(out).not.toContain(tok);
    expect(out).not.toContain('AWXYZ');
  });

  it('redacts a longer-than-spec AKIA-prefixed key without leaking bridging bytes', () => {
    // Canonical AKIA + 16. Synthetic AKIA + 18 + "WXYZ" = 26 chars total.
    const tok = 'AKIA' + 'B'.repeat(18) + 'WXYZ';
    const line = `aws_access_key_id=${tok}`;
    const out = redactSecretsInLine(line);
    expect(out).not.toContain(tok);
    expect(out).not.toContain('BWXYZ');
    expect(out).toMatch(/AKIA\.\.\.WXYZ/);
  });
});
