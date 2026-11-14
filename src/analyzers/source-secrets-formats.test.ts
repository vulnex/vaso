import { describe, it, expect } from 'vitest';
import { findSourceSecrets } from './source-secrets.js';

// Synthetic values in each vendor's shape; built at runtime so the literal
// tokens never sit in this file.
const tail = (n: number, alphabet = 'Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z'): string =>
  Array.from({ length: n }, (_, i) => alphabet[(i * 7) % alphabet.length]).join('');

describe('findSourceSecrets — token formats beyond API_KEY_PATTERNS', () => {
  const cases: Array<[string, string, string]> = [
    ['Google API key in a URL query', `fetch(\`https://maps.example.com/geocode?address=\${q}&key=AIza${tail(35)}\`);`, 'Google API key'],
    ['GitHub fine-grained PAT', `new Octokit({ auth: "github_pat_${tail(82)}" });`, 'GitHub fine-grained PAT'],
    ['GitHub app token', `const t = "ghs_${tail(36)}";`, 'GitHub token'],
    ['Hugging Face token', `new HfInference("hf_${tail(34)}");`, 'Hugging Face token'],
    ['Groq key as a ?? fallback', `new Groq({ apiKey: process.env.GROQ ?? "gsk_${tail(52)}" });`, 'Groq API key'],
    ['xAI key', `createXai("xai-${tail(80)}");`, 'xAI API key'],
    ['Stripe live secret key', `new Stripe("sk_live_${tail(99)}");`, 'Stripe secret key'],
    ['SendGrid key', `sgMail.setApiKey("SG.${tail(22)}.${tail(43)}");`, 'SendGrid API key'],
  ];
  for (const [label, code, kind] of cases) {
    it(`finds a ${label}, masked`, () => {
      const found = findSourceSecrets(code);
      expect(found.map((f) => f.kind)).toContain(kind);
      for (const f of found) expect(f.masked).toMatch(/^.{1,4}… \(\d+ chars\)$/);
    });
  }

  it('reports one finding per token, not one per matching format', () => {
    const found = findSourceSecrets(`const k = "sk-ant-${tail(40)}";`);
    expect(found).toHaveLength(1);
  });

  it('skips placeholders and token-shaped words in prose', () => {
    expect(findSourceSecrets('const k = "hf_your_token_here_xxxxxxxxxxxxxxxx";')).toEqual([]);
    expect(findSourceSecrets('// set GROQ_API_KEY to a gsk_ key from the console')).toEqual([]);
    expect(findSourceSecrets('const s = "SG.example";')).toEqual([]);
  });
});

describe('findSourceSecrets — keyed fallbacks', () => {
  const value = `Zx8${tail(21)}q7`;
  it('sees a secret-named key whose value is an env fallback', () => {
    for (const code of [
      `const cfg = { password: process.env.DB_PASSWORD ?? "${value}" };`,
      `const cfg = { apiKey: process.env["API_KEY"] || '${value}' };`,
      `api_key = os.environ.get("API_KEY") or "${value}"`,
      `token = os.getenv("SERVICE_TOKEN", "${value}")`,
    ]) {
      const found = findSourceSecrets(code);
      expect(found.map((f) => f.kind), code).toContain('secret-named value');
      expect(JSON.stringify(found)).not.toContain(value);
    }
  });

  it('does not take a non-secret fallback', () => {
    expect(findSourceSecrets('const cfg = { apiKey: process.env.API_KEY ?? "" };')).toEqual([]);
    expect(findSourceSecrets('const cfg = { token: process.env.TOKEN || "your-token-goes-here-123" };')).toEqual([]);
  });
});
