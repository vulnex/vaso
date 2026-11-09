import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm, chmod, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ScanContext, ParsedConfig, AgentInstallation, CheckModule } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { nanobotChecks } from './index.js';
import { riskyWhitelistEntry } from './nb-005-ssrf-webfetch.js';
import { isCatchAllPattern } from './nb-004-exec-tool-filter.js';

/**
 * A trimmed but shape-faithful `nanobot onboard` config.json (nanobot-ai
 * 0.3.x): scalar settings mixed into `channels`, null provider fields,
 * disabled channel templates (msteams ships host 0.0.0.0), always-on
 * websocket channel, defaults for api / gateway / tools.
 */
function onboardConfig(): Record<string, unknown> {
  return {
    agents: {
      defaults: {
        workspace: '~/.nanobot/workspace',
        modelPreset: null,
        model: 'anthropic/claude-opus-4-5',
        provider: 'auto',
        fallbackModels: [],
        dream: { enabled: true, intervalH: 2, modelOverride: null },
      },
    },
    channels: {
      sendProgress: true,
      sendToolHints: true,
      showReasoning: true,
      extractDocumentText: true,
      sendMaxRetries: 3,
      transcriptionProvider: 'groq',
      transcriptionLanguage: null,
      discord: { enabled: false, token: '', allowFrom: [], groupPolicy: 'mention' },
      msteams: { enabled: false, appId: '', appPassword: '', allowFrom: [], host: '0.0.0.0', port: 3978 },
      slack: {
        enabled: false, appToken: '', botToken: '', allowFrom: [], groupPolicy: 'mention',
        dm: { enabled: true, policy: 'open', allowFrom: [] },
      },
      telegram: { enabled: false, token: '', allowFrom: [], groupPolicy: 'mention', webhookListenHost: '127.0.0.1' },
      whatsapp: { enabled: false, allowFrom: [], groupPolicy: 'open' },
      nullChannel: null,
      websocket: { enabled: true },
    },
    transcription: { enabled: true, provider: null, model: null, language: null },
    providers: {
      custom: { apiKey: null, apiBase: null, apiType: 'auto', extraHeaders: null },
      anthropic: { apiKey: null, apiBase: null, apiType: 'auto', extraHeaders: null },
      openrouter: { apiKey: null, apiBase: null, apiType: 'auto', extraHeaders: null },
    },
    api: { host: '127.0.0.1', port: 8900, timeout: 120.0, apiKey: '' },
    gateway: { host: '127.0.0.1', port: 18790, restartMode: 'auto', heartbeat: { enabled: true, intervalS: 1800 } },
    tools: {
      web: { enable: true, proxy: null, search: { provider: 'duckduckgo', apiKey: '' }, fetch: { useJinaReader: true } },
      exec: {
        enable: true, timeout: 60, sandbox: '', sandboxRoBinds: [], sandboxRwBinds: [],
        allowedEnvKeys: [], allowPatterns: [], denyPatterns: [],
      },
      maxSessionMessagesPerMinute: 6,
      restrictToWorkspace: false,
      webuiAllowLocalServiceAccess: true,
      webuiAllowRemotePackageInstall: false,
      ssrfWhitelist: [],
    },
  };
}

type Json = Record<string, unknown>;
function merge(base: Json, patch: Json): Json {
  const out: Json = { ...base };
  for (const [k, v] of Object.entries(patch)) {
    const b = out[k];
    out[k] = v && typeof v === 'object' && !Array.isArray(v) && b && typeof b === 'object' && !Array.isArray(b)
      ? merge(b as Json, v as Json)
      : v;
  }
  return out;
}

const fs = new LocalFSProvider();
let home: string;
let dataDir: string;
let workspace: string;

beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), 'vaso-nb-'));
  dataDir = join(home, '.nanobot');
  workspace = join(dataDir, 'workspace');
  await mkdir(join(workspace, 'memory'), { recursive: true });
  await mkdir(join(workspace, 'skills'), { recursive: true });
  await mkdir(join(workspace, 'cron'), { recursive: true });
});

afterEach(async () => {
  await rm(home, { recursive: true, force: true });
});

async function makeCtx(data: Json): Promise<ScanContext> {
  // Point the default "~/.nanobot/workspace" at the temp home.
  const agents = (data.agents as Json | undefined) ?? {};
  const defaults = (agents.defaults as Json | undefined) ?? {};
  if (defaults.workspace === '~/.nanobot/workspace') defaults.workspace = workspace;
  const filePath = join(dataDir, 'config.json');
  const raw = JSON.stringify(data, null, 2);
  await writeFile(filePath, raw);
  await chmod(filePath, 0o600);
  const config: ParsedConfig = { raw, format: 'json', filePath, data };
  const installation: AgentInstallation = { agent: 'nanobot', installDir: dataDir, configFiles: [config] };
  return { installation, configs: [config], platform: process.platform, fs };
}

function check(id: string): CheckModule {
  const c = nanobotChecks.find(x => x.id === id);
  if (!c) throw new Error(`missing ${id}`);
  return c;
}

describe('Nanobot checks', () => {
  it('exports 12 checks in the nanobot category', () => {
    expect(nanobotChecks).toHaveLength(12);
    for (const c of nanobotChecks) {
      expect(c.category).toBe('nanobot');
      expect(c.supportedAgents).toContain('nanobot');
      expect(c.id).toMatch(/^NB-0\d{2}$/);
    }
  });

  it('never throws on an onboard-shaped config with null sections and scalar channel keys', async () => {
    const ctx = await makeCtx(onboardConfig());
    for (const c of nanobotChecks) {
      await expect(c.run(ctx)).resolves.toBeDefined();
    }
  });

  it('never throws when every section is null or missing', async () => {
    for (const data of [{}, { channels: null, tools: null, api: null, agents: null }, { channels: { websocket: null } }]) {
      const ctx = await makeCtx(data as Json);
      for (const c of nanobotChecks) {
        await expect(c.run(ctx)).resolves.toBeDefined();
      }
    }
  });

  it('on a stock onboard config only the permissive defaults fire (NB-003, NB-004)', async () => {
    const ctx = await makeCtx(onboardConfig());
    const failed: string[] = [];
    for (const c of nanobotChecks) {
      const r = await c.run(ctx);
      if (!r.passed) failed.push(r.id);
    }
    expect(failed.sort()).toEqual(['NB-003', 'NB-004']);
  });
});

describe('NB-001: channel open to any sender', () => {
  it('flags an enabled channel with allowFrom ["*"] as critical', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), {
      channels: { telegram: { enabled: true, token: '${TELEGRAM_TOKEN}', allowFrom: ['*'] } },
    }));
    const r = await check('NB-001').run(ctx);
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
    expect(r.evidence![0].detail).toContain('telegram');
  });

  it('passes empty allowFrom (pairing-only) and explicit IDs', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), {
      channels: {
        telegram: { enabled: true, allowFrom: [] },
        discord: { enabled: true, allowFrom: ['123456789'] },
      },
    }));
    expect((await check('NB-001').run(ctx)).passed).toBe(true);
  });

  it('ignores disabled channels and the token-gated websocket default ["*"]', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), {
      channels: {
        telegram: { enabled: false, allowFrom: ['*'] },
        websocket: { enabled: true, allowFrom: ['*'] },
      },
    }));
    expect((await check('NB-001').run(ctx)).passed).toBe(true);
  });

  it('flags an enabled Slack with the default open DM policy as a warning', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), { channels: { slack: { enabled: true } } }));
    const r = await check('NB-001').run(ctx);
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('warning');
    expect(r.evidence![0].snippet).toContain('dm.policy');
  });

  it('passes Slack with dm.policy allowlist', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), {
      channels: { slack: { enabled: true, dm: { policy: 'allowlist', allowFrom: ['U123'] } } },
    }));
    expect((await check('NB-001').run(ctx)).passed).toBe(true);
  });
});

describe('NB-002: plaintext secrets in config.json', () => {
  it('flags literal provider keys, channel tokens and MCP env secrets', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), {
      providers: { openrouter: { apiKey: 'sk-or-v1-0123456789abcdef0123456789abcdef' } },
      channels: { telegram: { enabled: true, token: '7000000000:AAtesttesttesttesttesttesttesttest00' } },
      tools: { mcpServers: { gh: { command: 'gh-mcp', env: { GITHUB_TOKEN: 'ghp_testtesttesttesttesttesttesttesttest0' } } } },
    }));
    const r = await check('NB-002').run(ctx);
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('warning');
    const paths = r.evidence!.map(e => e.snippet);
    expect(paths.some(p => p?.startsWith('providers.openrouter.apiKey'))).toBe(true);
    expect(paths.some(p => p?.startsWith('channels.telegram.token'))).toBe(true);
    expect(paths.some(p => p?.startsWith('tools.mcpServers.gh.env.GITHUB_TOKEN'))).toBe(true);
    // Never echo the secret
    expect(JSON.stringify(r.evidence)).not.toContain('0123456789abcdef0123');
  });

  it('accepts ${VAR} references, empty strings and nulls', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), {
      providers: { openrouter: { apiKey: '${OPENROUTER_API_KEY}' } },
      channels: { telegram: { enabled: true, token: '${TELEGRAM_TOKEN}' } },
    }));
    expect((await check('NB-002').run(ctx)).passed).toBe(true);
  });

  it('escalates to critical when config.json is world-readable and reachable', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), {
      providers: { anthropic: { apiKey: 'sk-ant-test-0123456789abcdefghij' } },
    }));
    await chmod(ctx.configs[0].filePath, 0o644);
    await chmod(home, 0o755);
    await chmod(dataDir, 0o755);
    const r = await check('NB-002').run(ctx);
    // Critical unless some ancestor of the temp dir blocks world traversal
    expect(['critical', 'warning']).toContain(r.severity);
    expect(r.passed).toBe(false);
  });
});

describe('NB-002: non-secret keys', () => {
  it('does not treat a string-valued websocketRequiresToken as a secret', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), { channels: { websocket: { websocketRequiresToken: 'true' } } }));
    expect((await check('NB-002').run(ctx)).passed).toBe(true);
  });
});

describe('NB-002: parent traversal', () => {
  it('stays a warning when a 0750 home blocks world access to a 0664 config', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), {
      providers: { anthropic: { apiKey: 'sk-ant-test-0123456789abcdefghij' } },
    }));
    await chmod(ctx.configs[0].filePath, 0o664);
    await chmod(dataDir, 0o775);
    await chmod(home, 0o750);
    const r = await check('NB-002').run(ctx);
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('warning');
    expect(JSON.stringify(r.evidence)).not.toContain('readable by all users');
  });
});

describe('NB-003: tools.restrictToWorkspace', () => {
  it('fails when false or unset and fixes the real key', async () => {
    const ctx = await makeCtx(onboardConfig());
    const r = await check('NB-003').run(ctx);
    expect(r.passed).toBe(false);
    expect(r.fixable).toBe(true);
    const fix = await check('NB-003').fix!(ctx);
    expect(fix.applied).toBe(true);
    const written = JSON.parse(await readFile(ctx.configs[0].filePath, 'utf-8'));
    expect(written.tools.restrictToWorkspace).toBe(true);
    // Never writes a top-level key (nanobot's root Config forbids extras)
    expect(written.restrictToWorkspace).toBeUndefined();
  });

  it('passes when tools.restrictToWorkspace is true', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), { tools: { restrictToWorkspace: true } }));
    expect((await check('NB-003').run(ctx)).passed).toBe(true);
  });

  it('accepts pydantic string booleans ("true") as enabled', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), { tools: { restrictToWorkspace: 'true' } }));
    expect((await check('NB-003').run(ctx)).passed).toBe(true);
  });

  it('honors the legacy tools.exec.restrictToWorkspace when the new key is absent', async () => {
    const data = onboardConfig();
    delete (data.tools as Json).restrictToWorkspace;
    ((data.tools as Json).exec as Json).restrictToWorkspace = true;
    const ctx = await makeCtx(data);
    expect((await check('NB-003').run(ctx)).passed).toBe(true);
  });
});

describe('NB-004: shell exec confinement', () => {
  it('warns when exec runs unsandboxed (default)', async () => {
    const r = await check('NB-004').run(await makeCtx(onboardConfig()));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('warning');
    expect(r.fixable).toBeFalsy();
  });

  it('is critical when a catch-all allow pattern disables the deny list', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), { tools: { exec: { sandbox: 'bwrap', allowPatterns: ['.*'] } } }));
    const r = await check('NB-004').run(ctx);
    expect(r.severity).toBe('critical');
    expect(r.evidence).toHaveLength(1);
  });

  it('passes with a sandbox and narrow binds, or with exec disabled', async () => {
    const sandboxed = await makeCtx(merge(onboardConfig(), {
      tools: { exec: { sandbox: 'bwrap', sandboxRoBinds: ['/opt/tools'] } },
    }));
    expect((await check('NB-004').run(sandboxed)).passed).toBe(true);
    const disabled = await makeCtx(merge(onboardConfig(), { tools: { exec: { enable: false } } }));
    expect((await check('NB-004').run(disabled)).passed).toBe(true);
  });

  it('judges allow patterns by what they match, not their spelling', async () => {
    for (const p of ['.*', '(?i).*', '.{0,}', '(.|\n)*', '[^\x00]*', '(?s).+', '\\S.*']) {
      expect(isCatchAllPattern(p), p).toBe(true);
    }
    for (const p of ['git (status|log|diff).*', 'ls( -la)?', '^npm test$', '(?i)echo .*', '[unclosed']) {
      expect(isCatchAllPattern(p), p).toBe(false);
    }
    const ctx = await makeCtx(merge(onboardConfig(), { tools: { exec: { sandbox: 'bwrap', allowPatterns: ['(?i).*', '.{0,}'] } } }));
    const r = await check('NB-004').run(ctx);
    expect(r.severity).toBe('critical');
    expect(r.evidence).toHaveLength(2);
  });

  it('treats a pydantic string "false" as disabling exec', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), { tools: { exec: { enable: 'false', allowPatterns: ['.*'] } } }));
    expect((await check('NB-004').run(ctx)).passed).toBe(true);
  });

  it('flags a sandbox bind of the home directory', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), {
      tools: { exec: { sandbox: 'bwrap', sandboxRwBinds: ['/home/test'] } },
    }));
    const r = await check('NB-004').run(ctx);
    expect(r.passed).toBe(false);
  });
});

describe('NB-005: SSRF whitelist', () => {
  it('classifies whitelist entries', () => {
    expect(riskyWhitelistEntry('0.0.0.0/0')).toBeDefined();
    expect(riskyWhitelistEntry('169.254.0.0/16')).toContain('metadata');
    expect(riskyWhitelistEntry('127.0.0.0/8')).toContain('loopback');
    expect(riskyWhitelistEntry('10.0.0.0/8')).toBeDefined();
    expect(riskyWhitelistEntry('::/0')).toBeDefined();
    expect(riskyWhitelistEntry('100.64.0.0/10')).toBeUndefined();
    expect(riskyWhitelistEntry('192.168.10.0/24')).toBeUndefined();
    expect(riskyWhitelistEntry('not-a-cidr')).toBeUndefined();
  });

  it('fails on a metadata-covering entry and passes the Tailscale example', async () => {
    const bad = await makeCtx(merge(onboardConfig(), { tools: { ssrfWhitelist: ['169.254.169.254/32'] } }));
    expect((await check('NB-005').run(bad)).passed).toBe(false);
    const ok = await makeCtx(merge(onboardConfig(), { tools: { ssrfWhitelist: ['100.64.0.0/10'] } }));
    expect((await check('NB-005').run(ok)).passed).toBe(true);
  });
});

describe('NB-006 / NB-007: workspace files writable by other users', () => {
  it('passes for default-mode files (existence is not a finding)', async () => {
    await writeFile(join(workspace, 'HEARTBEAT.md'), '# Heartbeat\n');
    await writeFile(join(workspace, 'memory', 'MEMORY.md'), '# Memory\n');
    await writeFile(join(workspace, 'SOUL.md'), '# Soul\n');
    await chmod(join(workspace, 'HEARTBEAT.md'), 0o664);
    await chmod(join(workspace, 'memory', 'MEMORY.md'), 0o664);
    const ctx = await makeCtx(onboardConfig());
    expect((await check('NB-006').run(ctx)).passed).toBe(true);
    expect((await check('NB-007').run(ctx)).passed).toBe(true);
  });

  it('flags world-writable HEARTBEAT.md and MEMORY.md', async () => {
    await writeFile(join(workspace, 'HEARTBEAT.md'), '# Heartbeat\n');
    await writeFile(join(workspace, 'memory', 'MEMORY.md'), '# Memory\n');
    await chmod(join(workspace, 'HEARTBEAT.md'), 0o666);
    await chmod(join(workspace, 'memory', 'MEMORY.md'), 0o666);
    const ctx = await makeCtx(onboardConfig());
    const hb = await check('NB-006').run(ctx);
    expect(hb.passed).toBe(false);
    expect(hb.evidence![0].file).toBe(join(workspace, 'HEARTBEAT.md'));
    const mem = await check('NB-007').run(ctx);
    expect(mem.passed).toBe(false);
    expect(mem.evidence!.some(e => e.file === join(workspace, 'memory', 'MEMORY.md'))).toBe(true);
  });

  it('downgrades to info when a parent blocks traversal', async () => {
    await writeFile(join(workspace, 'HEARTBEAT.md'), '# Heartbeat\n');
    await chmod(join(workspace, 'HEARTBEAT.md'), 0o666);
    await chmod(dataDir, 0o700);
    const r = await check('NB-006').run(await makeCtx(onboardConfig()));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('info');
    await chmod(dataDir, 0o755);
  });

  it('NB-006 skips when the heartbeat is disabled', async () => {
    await writeFile(join(workspace, 'HEARTBEAT.md'), '# Heartbeat\n');
    await chmod(join(workspace, 'HEARTBEAT.md'), 0o666);
    const ctx = await makeCtx(merge(onboardConfig(), { gateway: { heartbeat: { enabled: false } } }));
    expect((await check('NB-006').run(ctx)).passed).toBe(true);
  });

  it('follows a relocated agents.defaults.workspace', async () => {
    const other = join(home, 'elsewhere');
    await mkdir(other, { recursive: true });
    await writeFile(join(other, 'SOUL.md'), '# Soul\n');
    await chmod(join(other, 'SOUL.md'), 0o666);
    const ctx = await makeCtx(merge(onboardConfig(), { agents: { defaults: { workspace: other } } }));
    const r = await check('NB-007').run(ctx);
    expect(r.passed).toBe(false);
    expect(r.evidence![0].file).toBe(join(other, 'SOUL.md'));
  });
});

describe('NB-008: websocket / WebUI authentication', () => {
  it('passes the default loopback, token-required channel', async () => {
    expect((await check('NB-008').run(await makeCtx(onboardConfig()))).passed).toBe(true);
  });

  it('is critical on a LAN bind with token requirement disabled', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), {
      channels: { websocket: { enabled: true, host: '10.20.30.10', websocketRequiresToken: false } },
    }));
    const r = await check('NB-008').run(ctx);
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
  });

  it('warns on loopback without authentication', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), {
      channels: { websocket: { websocketRequiresToken: false } },
    }));
    const r = await check('NB-008').run(ctx);
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('warning');
  });

  it('flags an unprotected token-issue endpoint and remote package installs', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), {
      channels: { websocket: { host: '10.0.0.5', tokenIssuePath: '/auth/token', sslCertfile: '/etc/ssl/c.pem' } },
      tools: { webuiAllowRemotePackageInstall: true },
    }));
    const r = await check('NB-008').run(ctx);
    expect(r.severity).toBe('critical');
    expect(r.evidence).toHaveLength(2);
  });

  it('passes a remote bind with tokenIssueSecret and TLS', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), {
      channels: { websocket: { host: '10.0.0.5', tokenIssueSecret: '${WS_SECRET}', sslCertfile: '/etc/ssl/c.pem', sslKeyfile: '/etc/ssl/k.pem' } },
    }));
    expect((await check('NB-008').run(ctx)).passed).toBe(true);
  });

  it('needs both sslCertfile and sslKeyfile for wss:// (dt20 g5-F2)', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), {
      channels: { websocket: { host: '10.0.0.5', tokenIssueSecret: '${WS_SECRET}', ssl_certfile: '/etc/ssl/c.pem' } },
    }));
    const r = await check('NB-008').run(ctx);
    expect(r.passed).toBe(false);
    expect(r.evidence![0].detail).toMatch(/plaintext ws:\/\//);
  });

  it('reports an unauthenticated unix-socket channel as info, not a browser-reachable hole (dt20 g5-F5)', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), {
      channels: { websocket: { unixSocketPath: '/run/nanobot.sock', host: '0.0.0.0', websocketRequiresToken: false } },
    }));
    const r = await check('NB-008').run(ctx);
    expect(r.severity).toBe('info');
    expect(r.evidence![0].detail).toMatch(/unix socket \/run\/nanobot\.sock/);
    expect(r.evidence![0].detail).not.toMatch(/web page the user opens/);
  });
});

describe('NB-009: chat history permissions', () => {
  it('flags group/world-readable session jsonl under a traversable data dir', async () => {
    const sess = join(dataDir, 'sessions', '0123456789abcdef0123456789abcdef');
    await mkdir(sess, { recursive: true });
    await writeFile(join(sess, 'telegram_42.jsonl'), '{"role":"user"}\n');
    await chmod(join(sess, 'telegram_42.jsonl'), 0o644);
    const r = await check('NB-009').run(await makeCtx(onboardConfig()));
    expect(r.passed).toBe(false);
    expect(r.evidence!.some(e => e.file?.endsWith('telegram_42.jsonl'))).toBe(true);
  });

  it('passes owner-only history files', async () => {
    const sess = join(dataDir, 'sessions', 'abc');
    await mkdir(sess, { recursive: true });
    await writeFile(join(sess, 's.jsonl'), '{}\n');
    await chmod(join(sess, 's.jsonl'), 0o600);
    await writeFile(join(workspace, 'memory', 'history.jsonl'), '');
    await chmod(join(workspace, 'memory', 'history.jsonl'), 0o600);
    expect((await check('NB-009').run(await makeCtx(onboardConfig()))).passed).toBe(true);
  });
});

describe('NB-010: cron job store', () => {
  it('flags a world-writable <workspace>/cron/jobs.json', async () => {
    await writeFile(join(workspace, 'cron', 'jobs.json'), '{"version":1,"jobs":[]}');
    await chmod(join(workspace, 'cron', 'jobs.json'), 0o666);
    const r = await check('NB-010').run(await makeCtx(onboardConfig()));
    expect(r.passed).toBe(false);
    expect(r.evidence![0].file).toBe(join(workspace, 'cron', 'jobs.json'));
  });

  it('passes a default-mode job store', async () => {
    await writeFile(join(workspace, 'cron', 'jobs.json'), '{"version":1,"jobs":[]}');
    await chmod(join(workspace, 'cron', 'jobs.json'), 0o664);
    expect((await check('NB-010').run(await makeCtx(onboardConfig()))).passed).toBe(true);
  });
});

describe('NB-011: nanobot serve API authentication', () => {
  it('passes the loopback default', async () => {
    expect((await check('NB-011').run(await makeCtx(onboardConfig()))).passed).toBe(true);
  });

  it('is critical on a LAN bind without apiKey', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), { api: { host: '10.20.30.10', apiKey: '' } }));
    const r = await check('NB-011').run(ctx);
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
  });

  it('warns (plaintext HTTP) on a network bind with an apiKey', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), { api: { host: '0.0.0.0', apiKey: '${NANOBOT_API_KEY}' } }));
    const r = await check('NB-011').run(ctx);
    expect(r.severity).toBe('warning');
  });
});

describe('NB-012: unpinned MCP server packages', () => {
  it('flags npx/uvx without versions and passes pinned ones', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), {
      tools: {
        mcpServers: {
          fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'] },
          fetch: { command: 'uvx', args: ['mcp-server-fetch'] },
          pinned: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-memory@2025.8.4'] },
          pypinned: { command: 'uvx', args: ['mcp-server-time==2025.8.4'] },
          local: { command: '/usr/local/bin/my-mcp', args: [] },
          remote: { type: 'streamableHttp', url: 'https://mcp.example.com/mcp' },
        },
      },
    }));
    const r = await check('NB-012').run(ctx);
    expect(r.passed).toBe(false);
    expect(r.evidence).toHaveLength(2);
    expect(r.evidence!.map(e => e.snippet).join('\n')).toContain('tools.mcpServers.fs');
  });

  it('reads every runner the shared parser knows (uv tool run, npm exec, yarn dlx, env npx)', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), {
      tools: {
        mcpServers: {
          uvtool: { command: 'uv', args: ['tool', 'run', 'mcp-server-git'] },
          npmexec: { command: 'npm', args: ['exec', '--yes', 'some-mcp'] },
          yarndlx: { command: 'yarn', args: ['dlx', 'some-mcp@^1'] },
          envnpx: { command: '/usr/bin/env', args: ['npx', '-y', 'some-mcp'] },
          uvxfrom: { command: 'uvx', args: ['--from', 'mcp-server-time==2025.9.25', 'mcp-server-time'] },
          npmpinned: { command: 'npm', args: ['exec', '--yes', '--package=some-mcp@1.0.0', '--', 'some-mcp'] },
        },
      },
    }));
    const r = await check('NB-012').run(ctx);
    expect(r.evidence!.map(e => e.snippet!.split(':')[0]).sort()).toEqual([
      'tools.mcpServers.envnpx', 'tools.mcpServers.npmexec', 'tools.mcpServers.uvtool', 'tools.mcpServers.yarndlx',
    ]);
  });

  it('does not grep free text (skills mentioning npx are not MCP servers)', async () => {
    const ctx = await makeCtx(merge(onboardConfig(), { agents: { defaults: { botName: 'run npx something' } } }));
    expect((await check('NB-012').run(ctx)).passed).toBe(true);
  });
});
