import { describe, it, expect } from 'vitest';
import { findSourceSecrets } from './source-secrets.js';

const KEY = 'bjlYhhAS2VmyeiBuuHjiNw==E15AB7ko7tCzT0Yo';

describe('findSourceSecrets', () => {
  it('finds a hardcoded API key header (appsecco malicious-code-exec)', () => {
    const code = `const response = await fetch("https://api.api-ninjas.com/v2/randomquotes", {\n  headers: {\n    "X-Api-Key": "${KEY}"\n  }\n});`;
    expect(findSourceSecrets(code)).toEqual([
      { line: 3, kind: 'secret-named value', key: 'X-Api-Key', masked: 'bjlY… (40 chars)' },
    ]);
  });

  it('never returns the secret itself', () => {
    const found = findSourceSecrets(`apiKey = "${KEY}"`);
    expect(JSON.stringify(found)).not.toContain(KEY.slice(4));
  });

  it('finds known token formats and literal bearer tokens', () => {
    const kinds = findSourceSecrets([
      'const gh = "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB";',
      'headers: { Authorization: "Bearer a8f3K29dLw0qZx7Rt5Yu1Mn4Bv6Cx9Pz" }',
    ].join('\n')).map((s) => s.kind);
    expect(kinds).toEqual(['GitHub PAT', 'bearer token']);
  });

  it.each([
    ['env var name as value', 'const API_KEY: "OPENAI_API_KEY_VALUE" = 1; apiKeyEnv = "OPENAI_API_KEY"'],
    ['placeholder', 'apiKey: "your-api-key-goes-here-1234"'],
    ['interpolated from env', 'token: `${process.env.GITHUB_TOKEN_123456}`'],
    ['identifier', 'secretName: "clientSecretFieldName"'],
    ['URL', 'tokenUrl: "https://auth.example.com/oauth/token2"'],
    ['PEM header constant in a crypto library', 'const header = "-----BEGIN PRIVATE KEY-----";'],
    ['Python env lookup', 'API_KEY = os.environ.get("WEATHER_API_KEY")'],
  ])('ignores %s', (_label, code) => {
    expect(findSourceSecrets(code)).toEqual([]);
  });

  it('finds a Python module-level key', () => {
    expect(findSourceSecrets('API_KEY = "sk-a8f3K29dLw0qZx7Rt5Yu1Mn4Bv6"')).toHaveLength(1);
  });
});
