import { describe, it, expect, beforeAll } from 'vitest';
import type { AgentInstallation, AgentType, CheckResult, ParsedConfig, ScanContext } from '../core/types.js';
import { AGENT_TYPES } from '../core/types.js';
import { SnapshotFSProvider } from '../core/snapshot-fs-provider.js';
import { checkRegistry } from '../core/check-registry.js';
import { maskCredentialsDeep, maskCredentialsInLine, maskCredentialsInText, toReportJson } from '../reporting/serialize.js';
import { scanMemorySecrets } from '../analyzers/memory-secrets.js';
import { findHighEntropyBlocks } from '../analyzers/entropy.js';
import { redactSecretsInLine, secretShape } from '../core/patterns.js';
import { registerAllChecks } from './index.js';

/**
 * dt24 g4-F1: WS-003 quoted the first 8 characters of a plaintext secret
 * (`DB_PASSWORD=Tr0ub4do…`), and the report masker read the trailing `…` as a
 * placeholder, so every format printed it. Every check runs here against
 * configs holding planted secrets under the keys plaintext-secret checks
 * read; no report may carry a run of a secret beyond what reports show of a
 * long key (its first 8 and last 4 characters).
 */

const HOME = '/home/test';

// short secrets: no character of them is shown
const PASSWORD = 'Tr0ub4dor9q';
const SHORT_TOKEN = 'Zq7Wm3Kv8Rb2Lp';
// long keys: a known prefix, then the part no report may show
const OPENAI_KEY = 'sk-proj-Hq4Tz9Wm2Vb7Kc5Rn8Ld3Fs6Gj1Py0Aa';
const GITHUB_TOKEN = 'ghp_Jr5Qw8Mt2Zk7Vn4Hb9Lc3Ys6Fd1Gp0Ue2Wa';
const ENTROPIC = 'Mu5z1eQATYLId92VoWwSfcrv7qmRBnh6yOHk';

const SECRETS = [PASSWORD, SHORT_TOKEN, OPENAI_KEY, GITHUB_TOKEN, ENTROPIC];

/** What a report must never contain of `s`: any 6-character run of its hidden part. */
function windows(s: string): string[] {
  const hidden = s.length >= 24 ? s.slice(8, -4) : s;
  const out: string[] = [];
  for (let i = 0; i + 6 <= hidden.length; i++) out.push(hidden.slice(i, i + 6));
  return out;
}

const server = {
  command: 'npx',
  args: ['-y', 'some-mcp@1.2.3', '--api-key', OPENAI_KEY],
  env: { DB_PASSWORD: PASSWORD, OPENAI_API_KEY: OPENAI_KEY, AUTH_TOKEN: SHORT_TOKEN, SECRET: ENTROPIC },
  headers: { Authorization: `Bearer ${SHORT_TOKEN}`, 'X-Api-Key': PASSWORD },
  oauthClientSecret: PASSWORD,
  oauth: { clientSecret: PASSWORD },
};

const DATA: Record<string, unknown> = {
  env: { DB_PASSWORD: PASSWORD, ANTHROPIC_API_KEY: OPENAI_KEY, GITHUB_TOKEN, API_TOKEN: SHORT_TOKEN },
  mcpServers: { srv: server },
  mcp: { servers: [{ name: 'srv', ...server }], srv: server },
  tools: { mcpServers: { srv: server } },
  apiKey: PASSWORD,
  api_key: OPENAI_KEY,
  password: PASSWORD,
  token: SHORT_TOKEN,
  security: { auth: { apiKey: PASSWORD } },
  modelProviders: { openai: [{ id: 'm', apiKey: SHORT_TOKEN }] },
  providers: {
    openai: { apiKey: PASSWORD, api_key: SHORT_TOKEN, options: { apiKey: PASSWORD, headers: { 'X-Api-Key': SHORT_TOKEN } } },
  },
  llm: { providers: [{ id: 'p', apiKey: PASSWORD, headers: { Authorization: SHORT_TOKEN } }] },
  webhooks: { hook: { secret: PASSWORD } },
  model: { api_key: PASSWORD },
  github_token: GITHUB_TOKEN,
  SECRETS_MASTER_KEY: ENTROPIC,
  DB_PASSWORD: PASSWORD,
  OPENAI_API_KEY: OPENAI_KEY,
};

function emptyFs(): SnapshotFSProvider {
  return new SnapshotFSProvider({
    version: 1, hostname: 'test-host', platform: 'linux', homedir: HOME, timestamp: '2026-11-19T00:00:00Z',
    privilege: { uid: 1000, username: 'test', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['test'], skippedPaths: [] },
    files: {}, directories: {}, directoryModes: {}, commandOutputs: {}, env: {},
  });
}

function configsFor(dir: string): ParsedConfig[] {
  const raw = JSON.stringify(DATA, null, 2);
  const env = Object.entries(DATA).filter(([, v]) => typeof v === 'string').map(([k, v]) => `${k}=${v}`).join('\n');
  return [
    { raw, format: 'json', filePath: `${dir}/config.json`, data: DATA },
    { raw, format: 'json', filePath: `${dir}/mcp_config.json`, data: DATA },
    { raw, format: 'json', filePath: `${dir}/settings.json`, data: DATA },
    { raw: env, format: 'env', filePath: `${dir}/.env`, data: Object.fromEntries(env.split('\n').map(l => l.split('='))) },
  ] as ParsedConfig[];
}

describe('plaintext-secret evidence never quotes a secret', () => {
  beforeAll(() => {
    if (checkRegistry.getAll().length === 0) registerAllChecks();
  });

  const agents = AGENT_TYPES.filter(a => a !== 'mcp' && a !== 'skill-audit') as AgentType[];

  it.each(agents)('no report quotes a planted secret for %s', async (agent) => {
    const dir = `${HOME}/.${agent}`;
    const configs = configsFor(dir);
    const installation: AgentInstallation = { agent, installDir: dir, configFiles: configs, version: '1.0.0' };
    const ctx: ScanContext = { installation, configs, platform: 'linux', fs: emptyFs() };
    const results: CheckResult[] = [];
    for (const check of checkRegistry.getAll()) {
      if (check.supportedAgents && !check.supportedAgents.includes(agent)) continue;
      if (check.excludedAgents?.includes(agent)) continue;
      try {
        results.push(await check.run(ctx));
      } catch {
        // robustness.test.ts owns throwing checks
      }
    }
    const report = toReportJson(results);
    const leaks: string[] = [];
    for (const r of results) {
      const text = toReportJson(r);
      for (const s of SECRETS) {
        const hit = windows(s).find(w => text.includes(w));
        if (hit) leaks.push(`${r.id}: ${hit}`);
      }
    }
    expect(leaks).toEqual([]);
    expect(report.length).toBeGreaterThan(0);
  });

  it('reports print the shape as the check wrote it', () => {
    for (const s of ['DB_PASSWORD=<literal, 11 chars>', 'mcpServers.x.env.API_KEY: <literal, 40 chars>', 'Server "a": TOKEN=<literal, 24 chars>']) {
      expect(maskCredentialsInText(s)).toBe(s);
      expect(maskCredentialsInLine(s)).toBe(s);
    }
  });

  it('flags the planted secrets (the test reaches the checks it guards)', async () => {
    const flagged = new Set<string>();
    for (const agent of ['windsurf', 'devin', 'claude-code', 'qwen-code', 'gemini-cli', 'claude-desktop', 'hermes', 'abacus', 'atomic-agent'] as AgentType[]) {
      const dir = `${HOME}/.${agent}`;
      const configs = configsFor(dir);
      const ctx: ScanContext = { installation: { agent, installDir: dir, configFiles: configs, version: '1.0.0' }, configs, platform: 'linux', fs: emptyFs() };
      for (const check of checkRegistry.getAll()) {
        if (check.supportedAgents && !check.supportedAgents.includes(agent)) continue;
        if (check.excludedAgents?.includes(agent)) continue;
        try {
          const r = await check.run(ctx);
          if (!r.passed && r.evidence?.length) flagged.add(r.id);
        } catch { /* see robustness.test.ts */ }
      }
    }
    for (const id of ['WS-003', 'DEV-003', 'CC-004', 'QC-001', 'GEM-001', 'CD-001']) expect(flagged).toContain(id);
  });
});

/**
 * dt24 g8-R1/g5-R1/g4-R1: the shared helpers quoted the first and last 4
 * characters of a token (memory files, CFG-002/POL-002, entropy blocks) or
 * its first 4 (`mcp list` JSON). They print its kind and length only.
 */
describe('shared secret helpers print a secret\'s shape, no character of it', () => {
  beforeAll(() => {
    if (checkRegistry.getAll().length === 0) registerAllChecks();
  });

  const GITHUB_TOKEN = 'ghp_Jr5Qw8Mt2Zk7Vn4Hb9Lc3Ys6Fd1Gp0Ue2Wax';

  /** No 4-character run of `s` in `text`. */
  function quotes(text: string, s: string): string | undefined {
    for (let i = 0; i + 4 <= s.length; i++) if (text.includes(s.slice(i, i + 4))) return s.slice(i, i + 4);
    return undefined;
  }

  it('memory files: known tokens and high-entropy strings', () => {
    const blob = 'Q9w8E7r6T5y4U3i2O1p0AaSsDdFfGgHhJjKkLlZzXxCcVvBbNnMm+/';
    const ev = scanMemorySecrets('/h/AGENTS.md', `Use ${GITHUB_TOKEN} for the API\nThe blob is "${blob}" here\n`);
    expect(ev.map(e => e.snippet)).toEqual([`<literal, ${GITHUB_TOKEN.length} chars, GitHub PAT>`, `<literal, ${blob.length} chars, high-entropy string>`]);
    for (const e of ev) {
      expect(quotes(toReportJson(e), GITHUB_TOKEN.slice(4))).toBeUndefined();
      expect(quotes(toReportJson(e), blob)).toBeUndefined();
    }
  });

  it('entropy blocks', () => {
    const [b] = findHighEntropyBlocks(`const k = "${ENTROPIC}";`, 4.5, 30);
    expect(b.snippet).toBe(`<literal, ${ENTROPIC.length} chars, high-entropy string>`);
  });

  it('CFG-002: the token\'s kind and length, around the match in a one-line config', async () => {
    const random = 'Hk3Lq9Zm2Vx7Rt5Wb8Nc4Py1Jd6Gs0Fa';
    const raw = JSON.stringify({ sessionId: random, region: 'eu-west-1', theme: 'dark', retries: 3, timeoutMs: 30000, logLevel: 'info', apiKey: OPENAI_KEY });
    const configs = [{ raw, format: 'json', filePath: `${HOME}/.openclaw/openclaw.json`, data: JSON.parse(raw) }] as ParsedConfig[];
    const ctx: ScanContext = { installation: { agent: 'openclaw', installDir: `${HOME}/.openclaw`, configFiles: configs }, configs, platform: 'linux', fs: emptyFs() };
    const r = await checkRegistry.getAll().find(c => c.id === 'CFG-002')!.run(ctx);
    expect(r.passed).toBe(false);
    const text = toReportJson(r);
    expect(text).toContain(`<literal, ${OPENAI_KEY.length} chars, OpenAI API key>`);
    expect(quotes(text, OPENAI_KEY.slice(8))).toBeUndefined();
    expect(quotes(text, random)).toBeUndefined();
  });

  it('mcp list JSON: env and header values', () => {
    const out = toReportJson({ configs: [{ servers: [{ name: 's', env: { GITHUB_TOKEN, DB_PASSWORD: PASSWORD }, headers: { Authorization: `Bearer ${SHORT_TOKEN}` } }] }] });
    for (const s of [GITHUB_TOKEN, PASSWORD, SHORT_TOKEN]) expect(quotes(out, s)).toBeUndefined();
    const terminal = JSON.stringify(maskCredentialsDeep({ env: { GITHUB_TOKEN } }));
    expect(quotes(terminal, GITHUB_TOKEN)).toBeUndefined();
  });

  it('redactSecretsInLine (CFG-002, POL-002, skill descriptions)', () => {
    const out = redactSecretsInLine(`token: ${GITHUB_TOKEN}`);
    expect(out).toBe(`token: <literal, ${GITHUB_TOKEN.length} chars, GitHub PAT>`);
    // the report masker keeps the shape as written
    expect(maskCredentialsInLine(out)).toBe(out);
    expect(JSON.parse(toReportJson({ snippet: `"apiKey":"${secretShape(OPENAI_KEY, 'OpenAI API key')}"` })).snippet).toContain('OpenAI API key');
  });
});
