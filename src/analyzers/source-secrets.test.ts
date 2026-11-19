import { describe, it, expect } from 'vitest';
import { findSourceSecrets } from './source-secrets.js';

const KEY = 'bjlYhhAS2VmyeiBuuHjiNw==E15AB7ko7tCzT0Yo';

describe('findSourceSecrets', () => {
  it('finds a hardcoded API key header (appsecco malicious-code-exec)', () => {
    const code = `const response = await fetch("https://api.api-ninjas.com/v2/randomquotes", {\n  headers: {\n    "X-Api-Key": "${KEY}"\n  }\n});`;
    expect(findSourceSecrets(code)).toEqual([
      { line: 3, kind: 'secret-named value', key: 'X-Api-Key', masked: '<literal, 40 chars>' },
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

  it.each([
    ['apiKey', `const apiKey = "${KEY}";`],
    ['token', `client({ token: "${KEY}" })`],
    ['password', `password: '${KEY}',`],
    ['secret', `secret = "${KEY}"`],
  ])('finds a bare %s assignment', (key, code) => {
    expect(findSourceSecrets(code).map((s) => s.key)).toEqual([key]);
  });

  it('finds a Python module-level key', () => {
    expect(findSourceSecrets('API_KEY = "sk-a8f3K29dLw0qZx7Rt5Yu1Mn4Bv6"')).toHaveLength(1);
  });
});

describe('findSourceSecrets — documented public values (dt13 realworld2)', () => {
  it("drops Upstash's documented QStash local-dev token", () => {
    const code = 'var LOCAL_QSTASH_TOKEN = "eyJVc2VySUQiOiJkZWZhdWx0VXNlciIsIlBhc3N3b3JkIjoiZGVmYXVsdFBhc3N3b3JkIn0=";';
    expect(findSourceSecrets(code)).toEqual([]);
  });

  it('marks a key the code documents as public by design, and keeps an undocumented one plain', () => {
    const lara = [
      '/**',
      ' * The key is public by design — it ships in the npm package —',
      ' * and only buys short-lived ingest tokens for the `mcp` channel.',
      ' */',
      'const DEFAULT_METRICS_URL = "https://integration-metrics.laratranslate.com";',
      'const DEFAULT_METRICS_API_KEY = "fef79db0da00dd07752b3cbffa89f5e911617aa943a338c7";',
    ].join('\n');
    expect(findSourceSecrets(lara)).toMatchObject([{ line: 6, declaredPublic: true }]);
    const real = 'const DEFAULT_METRICS_API_KEY = "fef79db0da00dd07752b3cbffa89f5e911617aa943a338c7";';
    expect(findSourceSecrets(real)[0].declaredPublic).toBeUndefined();
  });

  it('stays linear on a long a-b-c name run and keeps whole and flag-style key names (dt15 P10)', () => {
    const start = Date.now();
    findSourceSecrets(`${'a-'.repeat(50_000)}\n${'token-'.repeat(17_000)}\n`);
    expect(Date.now() - start).toBeLessThan(1000);
    expect(findSourceSecrets(`const x = { "my-service-api-key": "${KEY}" };`)[0]?.key).toBe('my-service-api-key');
    expect(findSourceSecrets(`args.push("--api-key=" , "x"); opts = { "9-token": "${KEY}" };`)[0]?.key).toBe('token');
  });
});
