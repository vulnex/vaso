import { describe, it, expect } from 'vitest';
import { isPlaceholderSecret, isSecretReference, redactSecret, redactSecretsInLine, truncateSnippet } from './patterns.js';

describe('isSecretReference (dt17 MD-C)', () => {
  it('knows secret manager references, key files, profile names and env references', () => {
    for (const v of ['op://Private/GitHub/credential', 'arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/x-AbC123',
      'vault:secret/data/mcp#token', 'projects/p-1/secrets/tok', 'https://kv1.vault.azure.net/secrets/tok',
      '@Microsoft.KeyVault(SecretUri=https://kv1.vault.azure.net/secrets/tok/)', 'ENC[AES256_GCM,data:abc=,type:str]',
      'service-account-key.json', '~/.config/x.json', 'production-us-east-2', 'default', '${GITHUB_TOKEN}', 'Bearer {env:TOKEN}']) {
      expect(isSecretReference(v), v).toBe(true);
    }
  });

  it('is never a literal secret', () => {
    for (const v of ['ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8', 'q7Zp2Lk9Vx4Rt8Mw3Nc6Bh1Jd5Fg0Sa', 'pass:hunter2hunter2',
      'correct-horse-battery-staple', 'sk-proj-' + 'Zq3xV9mK2pL8nR4tW7yB1cD6fG0hJ5sA', '']) {
      expect(isSecretReference(v), v).toBe(false);
    }
  });
});

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

  it('truncates long lines after redaction with a spaced trailing ellipsis', () => {
    const filler = 'host: 127.0.0.1, '.repeat(10);
    const out = redactSecretsInLine(filler, 80);
    expect(out).toBe(`${filler.slice(0, 80)} ...`);
    expect(out.endsWith(' ...')).toBe(true);
  });

  // dt20 g8-F2: the cut value ended in `...` and the report masker took it
  // for a placeholder, printing 42 characters of the password
  it('keeps at most 8 characters of a value the cut falls inside', () => {
    const pw = 'Zp9Yx8Wv7Ut6Sr5Qp4On3Ml2Kj1Ih0Gf9Ed8Cb7Aa6Ee5';
    const line = `{"note":"sk-proj-${'A'.repeat(30)}","db_password":"${pw}"}`;
    const out = redactSecretsInLine(line);
    expect(out).not.toContain(pw.slice(0, 9));
    expect(out).toContain('"db_password":"Zp9Yx8Wv ...');
    expect(truncateSnippet('x'.repeat(150), 80)).toBe('xxxxxxxx ...');
    expect(truncateSnippet('short', 80)).toBe('short');
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

describe('isPlaceholderSecret', () => {
  it('recognizes documentation placeholders', () => {
    for (const v of [
      'sk-ant-your-actual-anthropic-key-here', 'ghp_your_token', 'sk-ant-...', 'sk-…here',
      '<your-api-key>', '{{API_KEY}}', 'sk-xxxxxxxxxxxxxxxxxxxx', 'AKIAIOSFODNN7EXAMPLE', 'changeme', 'your-key-here',
    ]) expect(isPlaceholderSecret(v), v).toBe(true);
  });

  it('leaves realistic keys alone', () => {
    for (const v of [
      'sk-ant-api03-Zx9Qw3Er7Ty1Ui5Op2As6Df4Gh8Jk0LzXc-Vb7NmQwErTy', 'ghp_Zx9Qw3Er7Ty1Ui5Op2As6Df4Gh8Jk0LzXcVb',
      'AKIAZ7QX4M2PLR5TNW3B', 'sk-or-v1-0123456789abcdef0123456789abcdef', 'xoxb-1234567890-abcdefghijkl',
    ]) expect(isPlaceholderSecret(v), v).toBe(false);
  });
});

describe('envReference', () => {
  it('recognizes every agent\'s reference syntax', async () => {
    const { envReference } = await import('./patterns.js');
    expect(envReference('${env:TOKEN}')).toBe('env-colon');
    expect(envReference('${file:/run/secrets/x}')).toBe('env-colon');
    expect(envReference('{env:TOKEN}')).toBe('brace-env');
    expect(envReference('${TOKEN}')).toBe('dollar-brace');
    expect(envReference('${TOKEN:-dev}')).toBe('dollar-brace');
    expect(envReference('$TOKEN')).toBe('dollar');
    expect(envReference('Bearer ${MCP_TOKEN}')).toBe('dollar-brace');
    expect(envReference('$env:TOKEN')).toBe('powershell');
    expect(envReference('%TOKEN%')).toBe('percent');
    expect(envReference('GITHUB_PERSONAL_ACCESS_TOKEN')).toBe('name');
  });

  it('never treats a stored credential as a reference', async () => {
    const { envReference } = await import('./patterns.js');
    for (const v of ['sk-live-abcdef1234567890', 'Bearer sk-live-abcdef1234567890', 'AKIAZ3MPLE7TOKENX2QR', 'Bearer ${A} sk-live-abc123def456',
      '${TOKEN:-sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123}', '${TOKEN:-a1b2c3d4e5f6g7h8i9j0}', 'hunter2hunter2', 'abc_def']) {
      expect(envReference(v), v).toBeUndefined();
    }
  });
});


describe('envReference: a $-value is a reference only when its name is variable-shaped', () => {
  it('keeps variable references', async () => {
    const { isEnvReference } = await import('./patterns.js');
    for (const v of ['$GITHUB_TOKEN', '${API_KEY}', '$api_key', '${apiKey}', '$HOME', 'Bearer ${MCP_TOKEN}', '$env:OPENAI_API_KEY', '%APPDATA%', '${env:TOKEN}', '{env:KEY}', 'GITHUB_TOKEN']) {
      expect(isEnvReference(v), v).toBe(true);
    }
  });
  it('treats a password that starts with $ as a value, not a reference', async () => {
    const { isEnvReference } = await import('./patterns.js');
    for (const v of ['$Zx8f3kq9Lm2Pq7Rt', '${Zx8f3kq9Lm2Pq7Rt}', 'Bearer $Zx8f3kq9Lm2Pq7Rt']) {
      expect(isEnvReference(v), v).toBe(false);
    }
  });
});
