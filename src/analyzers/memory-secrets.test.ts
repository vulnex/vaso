import { describe, it, expect, vi } from 'vitest';
import type { AgentType, CheckModule, ScanContext } from '../core/types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { memorySecretSeverity, scanMemorySecrets } from './memory-secrets.js';
import { cc012 } from '../checks/claude-code/cc-012-memory-secret-leak.js';
import { cdx007 } from '../checks/codex/cdx-007-memory-secret-leak.js';
import { opc007 } from '../checks/opencode/opc-007-memory-secret-leak.js';
import { gem010 } from '../checks/gemini-cli/gem-010-memory-secrets.js';
import { qc010 } from '../checks/qwen-code/qc-010-memory-secrets.js';
import { ghc008 } from '../checks/copilot-cli/ghc-008-instructions-secrets.js';
import { dev007 } from '../checks/devin/dev-007-agents-md-secrets.js';

// Shapes of current OpenAI keys (fake bodies)
const PROJ = 'sk-proj-' + 'Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z_Ab3dEf6hIj9kLm2-nOp5qRs8tUv';
const SVCACCT = 'sk-svcacct-' + 'Zy9xWv8uTs7rQp6oNm5lKj4iHg3fEd2cBa1_Zy9xWv8uTs7rQp6';
const ADMIN = 'sk-admin-' + 'Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G5h6J7k8L9z0X1c2V3b4';
const LEGACY = 'sk-' + 'T3BlbkFJ'.repeat(6);

describe('scanMemorySecrets', () => {
  it.each([PROJ, SVCACCT, ADMIN, LEGACY])('recognises %s as an OpenAI key (critical)', (key) => {
    const ev = scanMemorySecrets('/r/CLAUDE.md', `Deploy with OPENAI_API_KEY=${key}\n`);
    expect(ev).toHaveLength(1);
    expect(ev[0].detail).toBe('Plaintext OpenAI API key in memory file');
    expect(memorySecretSeverity(ev)).toBe('critical');
  });

  it('reports one item per line even when several formats overlap', () => {
    const ev = scanMemorySecrets('/r/AGENTS.md', `ghp_${'a1B2'.repeat(10)}`);
    expect(ev).toHaveLength(1);
  });

  it('does not read a key inside another word', () => {
    expect(scanMemorySecrets('/r/AGENTS.md', 'mount disk-0123456789abcdefghijklmnop')).toEqual([]);
  });

  it('skips documentation placeholders', () => {
    expect(scanMemorySecrets('/r/AGENTS.md', 'export OPENAI_API_KEY=sk-proj-your-api-key-goes-here-xxxx')).toEqual([]);
  });

  it('a high-entropy string with no known prefix is a warning', () => {
    const ev = scanMemorySecrets('/r/AGENTS.md', 'seed "MuK5z1eQATYLId92VoWwSfcrv7qmRBnh6yOHkxsjtP3abFCNg4lXGi0E"');
    expect(ev).toHaveLength(1);
    expect(ev[0].detail).toMatch(/High-entropy/);
    expect(memorySecretSeverity(ev)).toBe('warning');
  });

  // dt20 g6-F4: keyed credentials in prose were missed (too short or unquoted
  // for the entropy scan)
  it.each([
    ['DB_PASSWORD=Pq7Wz2Lk9Xv4Rt8Ns3Jm6Hb1', 'DB_PASSWORD', 'Pq7Wz2Lk9Xv4Rt8Ns3Jm6Hb1'],
    ['- api_key: Mq3Zx8Lp2Vn7Rk4Tw9Yb6Hd1Fs5Gj0', 'api_key', 'Mq3Zx8Lp2Vn7Rk4Tw9Yb6Hd1Fs5Gj0'],
    ['Use `"client_secret": "Kp4Ry7Ws2Zn9Lq3Vx8Mb5Td1"` for staging.', 'client_secret', 'Kp4Ry7Ws2Zn9Lq3Vx8Mb5Td1'],
    ['curl -H "Authorization: Bearer Zr8Ty3Uw6Qa1Sx4Dc7Fv9Gb2Hn5Jm0Kl" https://api.example.com', 'Authorization', 'Zr8Ty3Uw6Qa1Sx4Dc7Fv9Gb2Hn5Jm0Kl'],
    ['* token = "Mq7Wz2Lk9Xv4Rt8Ns3JmQ"', 'token', 'Mq7Wz2Lk9Xv4Rt8Ns3JmQ'],
    ['| API_KEY | Oq7Wz2Lk9Xv4Rt8Ns3JmPa |', 'API_KEY', 'Oq7Wz2Lk9Xv4Rt8Ns3JmPa'],
    ['export GITHUB_TOKEN="Qq7Wz2Lk9Xv4Rt8Ns3JmRb"', 'GITHUB_TOKEN', 'Qq7Wz2Lk9Xv4Rt8Ns3JmRb'],
    ['**API key**: Uq7Wz2Lk9Xv4Rt8Ns3JmVc', 'API key', 'Uq7Wz2Lk9Xv4Rt8Ns3JmVc'],
    ['WEBHOOK_SECRET: 3f9a1c7e2b8d4f6a0c5e9b1d7f3a8c2e', 'WEBHOOK_SECRET', '3f9a1c7e2b8d4f6a0c5e9b1d7f3a8c2e'],
  ])('flags the keyed credential in %s (warning, value never quoted)', (line, name, value) => {
    const ev = scanMemorySecrets('/r/CLAUDE.md', `# notes\n${line}\n`);
    expect(ev).toHaveLength(1);
    expect(ev[0].line).toBe(2);
    expect(ev[0].snippet).toBe(`${name}: <literal, ${value.length} chars>`);
    expect(memorySecretSeverity(ev)).toBe('warning');
  });

  it.each([
    'password: see the vault entry',
    'token: ${GITHUB_TOKEN}',
    'api_key: $OPENAI_API_KEY',
    'client_secret: op://Private/app/secret',
    'API_KEY=your-api-key-here-1234',
    'SECRET_ARN=arn:aws:secretsmanager:us-east-1:123456789012:secret:prod-AbCdEf',
    'token_url: https://auth.example.com/oauth2/token',
    'SSH_PUBLIC_KEY: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq8vJ3kLm9Pq2Rs5Tv8Wy1Ab4Cd6Ef0GhJkLmNoPqRs',
    'password: hunter2hunter2',
    'The token cache key is gemini-session-cache-v2',
    'Tokens: max_tokens=4096 per request',
    'const token = getTokenFor2024Release(userId)',
    'password = os.environ["DB_PASSWORD_2024"]',
    // g6 re-verify: password hashes and digests are not the secret
    'password_hash: bcrypt$2b$12$KIXQJ3wq0y8sYlE2zFh6Ue',
    'password: $argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$Zq8xL2vN7pR4tW9yB3dF6hJ1',
    'cache_key: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'key_fingerprint: Zq8xL2vN7pR4tW9yB3dF6hJ1kM5n',
  ])('does not flag %s', (line) => {
    expect(scanMemorySecrets('/r/CLAUDE.md', line)).toEqual([]);
  });

  it('reads a quoted value to its closing quote (snippet length is the whole value)', () => {
    for (const [line, len] of [['signing_secret: "L1mHoOsFaQfDPr;AJ71fTquWoGsbe"', 29], ['signing_secret: "KXgzg2sye9b2Ra nn76dEyTzAeKOm"', 29], ["token: 'Ab3De5Fg7Hj9Kl1Mn3Pq'", 20]] as const) {
      const ev = scanMemorySecrets('/r/CLAUDE.md', line);
      expect(ev).toHaveLength(1);
      expect(ev[0].snippet).toMatch(new RegExp(`<literal, ${len} chars>$`));
    }
  });

  it('reads `*` bullet lines with the entropy scan (they are prose, not comment continuations)', () => {
    const ev = scanMemorySecrets('/r/CLAUDE.md', '* seed "MuK5z1eQATYLId92VoWwSfcrv7qmRBnh6yOHkxsjtP3abFCNg4lXGi0E"');
    expect(ev).toHaveLength(1);
    expect(ev[0].detail).toMatch(/High-entropy/);
  });

  it('a mitigated credential does not make the result critical', () => {
    const ev = scanMemorySecrets('/r/AGENTS.md', `key ${PROJ}`).map(e => Object.assign(e, { mitigated: true }));
    expect(memorySecretSeverity(ev)).toBe('warning');
  });
});

// Every memory-file check uses the same formats and the same tiering
const MODULES: Array<[CheckModule, AgentType, string]> = [
  [cc012, 'claude-code', '/home/t/.claude'],
  [cdx007, 'codex', '/home/t/.codex'],
  [opc007, 'opencode', '/home/t/.config/opencode'],
  [gem010, 'gemini-cli', '/home/t/.gemini'],
  [qc010, 'qwen-code', '/home/t/.qwen'],
  [ghc008, 'copilot-cli', '/home/t/.copilot'],
  [dev007, 'devin', '/home/t/.config/devin'],
];

const CHECKS = MODULES.map(([c, a, d]) => [c.id, c, a, d] as const);

function ctxWith(agent: AgentType, installDir: string, content: string): ScanContext {
  const fs = {
    access: vi.fn(async () => true),
    readFile: vi.fn(async () => content),
    readdir: vi.fn(async () => []),
    readdirEntries: vi.fn(async () => []),
    homedir: () => '/home/t',
    platform: 'linux',
  } as unknown as FSProvider;
  return { installation: { agent, installDir, configFiles: [] }, configs: [], platform: 'linux', fs };
}

describe('memory-file secret checks', () => {
  it.each(CHECKS)('%s flags an sk-proj- key as critical', async (_id, check, agent, dir) => {
    const r = await check.run(ctxWith(agent, dir, `Use ${PROJ} for the API`));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
  });

  it.each(CHECKS)('%s reports a high-entropy string alone as a warning', async (_id, check, agent, dir) => {
    const r = await check.run(ctxWith(agent, dir, 'token: "MuK5z1eQATYLId92VoWwSfcrv7qmRBnh6yOHkxsjtP3abFCNg4lXGi0E"'));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('warning');
  });

  it.each(CHECKS)('%s passes clean prose', async (_id, check, agent, dir) => {
    const r = await check.run(ctxWith(agent, dir, '# Notes\n\nRun the tests before committing.\n'));
    expect(r.passed).toBe(true);
  });
});

describe('dt20 re-verify 5: Airtable personal access tokens', () => {
  const pat = `patQ7wX2mZ9kL4vB8.${'3f9a1c7e5b2d4680'.repeat(4)}`;
  it('is a known key format in prose and under a key name', () => {
    const bare = scanMemorySecrets('/r/CLAUDE.md', `Use ${pat} for the base.\n`);
    expect(bare.map(e => e.detail)).toEqual(['Plaintext Airtable personal access token in memory file']);
    const keyed = scanMemorySecrets('/r/CLAUDE.md', `AIRTABLE_TOKEN=${pat}\n`);
    expect(keyed[0].detail).toBe('Plaintext Airtable personal access token in memory file');
    expect(JSON.stringify([bare, keyed])).not.toContain(pat.slice(0, 16));
  });
});

describe('dt21: snippets, bold labels, large files', () => {
  // known formats from the dt21 masking fixture (fake bodies)
  const KEYS = [
    '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',
    'xai-jqevt0MLaMRTvetw0tESulEETldq8b8Vw2zbJYAxyL1aCcTlN99mhWp708DwGw5HqXDgLVXZx3scB8fn',
    'sk-ant-api03-Q7rT2mZ9kLp4Vw8NcB1dYh6Ju3Fs0GxEa5Ri',
    'xoxa-2-quQrDs0GPRZwwrPwV81Aw71l33SCx9vHjHkm1x72',
    'patEsSfUQUAkNX7LH.d98065e5751f75143a5f61debc267b0bc8d3b1939a9b4ddbe45cf642b0c3a4ac',
    `ghp_${'a1B2'.repeat(10)}`,
  ];

  it('no snippet shows more than 8 characters of a key', () => {
    const ev = scanMemorySecrets('/r/CLAUDE.md', KEYS.map(k => `- use ${k} here`).join('\n'));
    expect(ev.length).toBeGreaterThanOrEqual(4);
    for (const k of KEYS) {
      for (let i = 0; i + 9 <= k.length; i++) {
        expect(JSON.stringify(ev), k).not.toContain(k.slice(i, i + 9));
      }
    }
  });

  it('reads a colon inside the bold markers (**API key:** …)', () => {
    const ev = scanMemorySecrets('/r/CLAUDE.md', '**API key:** Zq8wX3mK9pL2vB7nR4tY\n**Token**: Hn4bV7cX1zM8qW2eR5tY\n');
    expect(ev.map(e => e.line)).toEqual([1, 2]);
  });

  it('scans a large file in linear time', () => {
    const lines = Array.from({ length: 130_000 }, (_, i) => (i % 2 ? `password: Zq8wX3mK9pL2vB7n${i}` : `line ${i} of notes`));
    const start = Date.now();
    expect(scanMemorySecrets('/r/CLAUDE.md', lines.join('\n')).length).toBeGreaterThan(60_000);
    expect(Date.now() - start).toBeLessThan(10_000);
  });
});

describe('dt21 round 2: identifier keys', () => {
  it('does not read an ID under an "… key" name as a credential', () => {
    const md = ['Idempotency key: 7f3a9c1e2b4d6f8a0c5e', 'Cache key: user_8f3k2m9q4p7x1z6w', 'S3 key: uploads/2026/Xq7Lk2Pz9Rt4Vw8Y.png',
      'Partition key: tenant_9Zx8Lp2Vn7Rk4Tw9', 'Signing key: Zq8wX3mK9pL2vB7nR4tY'].join('\n');
    expect(scanMemorySecrets('/r/AGENTS.md', md).map(e => e.line)).toEqual([5]);
  });

  it('reports Azure access keys under Primary/Storage/… key names, and key-shaped values under any name', () => {
    const b64 = 'CPiPYCXVSCjFjI4ukDiD6ZFGJOPkxb9+meWXF76cZNnmA95SbnITHMPcaeUBr+UykT/B2SywgD2jgg9rmrkJPA==';
    const md = [`Primary key: ${b64}`, `Storage key: ${b64.replace('C', 'D')}`, `Cosmos DB primary key: ${b64.replace('C', 'E')}`,
      'Event Hubs primary key: OnDMyo2YKy4ZkGVnhIPCEt0xUAfVO59Z', 'Primary key: 52d22d2d857669119dc7e9003d0cafc1',
      'Blob key: 5bC5SdWi5bY3VGkGrTIaST631GXEEqgn', 'Registry key: uOVFu67zc2FPiTFmfgaxlbXd2wDSNnWS', 'KV key: uwbPEl8i0KcjC6WdGGeaCttHNYDS20AR',
      'Index key: uJXl15DdhmS6lIt4ddAFhLcBm1t3YW0C', 'Redis key: efYfbYOybGLC7EeNxymfmLNcdz4NFucZ',
      `Cache key: ${b64.replace('C', 'F')}`, 'Idempotency key: 52d22d2d857669119dc7e9003d0cafc2'].join('\n');
    expect(scanMemorySecrets('/r/CLAUDE.md', md).map(e => e.line)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12]); // line 10's value isn't random enough (as in round 1)
  });
});

// dt24 g4-R2: the probe disguises the strings this rule reports in memory
// files (probe/secret_scrub_memory.go); both read this table
describe('memory-file entropy rule (probe parity)', () => {
  it('reports the quoted strings of probe/testdata/memory-entropy-cases.json as the probe finds them', async () => {
    const { readFile } = await import('node:fs/promises');
    const { resolve } = await import('node:path');
    const cases = JSON.parse(await readFile(resolve(import.meta.dirname, '../../probe/testdata/memory-entropy-cases.json'), 'utf-8')) as Array<{ line: string; flagged: boolean }>;
    expect(cases.length).toBeGreaterThanOrEqual(10);
    for (const c of cases) {
      const ev = scanMemorySecrets('/h/AGENTS.md', `# Notes\n\n${c.line}\n`).filter(e => e.detail?.startsWith('High-entropy'));
      expect(ev.length > 0, c.line).toBe(c.flagged);
    }
  });
});
