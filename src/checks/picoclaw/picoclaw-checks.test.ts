import { describe, it, expect, afterEach } from 'vitest';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { AgentInstallation, ParsedConfig, ScanContext } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { picoclawChecks } from './index.js';

const HOME = new LocalFSProvider().homedir();
const CONFIG = '/home/test/.picoclaw/config.json';
const LAUNCHER = '/home/test/.picoclaw/launcher-config.json';

type Json = Record<string, unknown>;

/** Shape of `picoclaw onboard` output (schema v3), trimmed to the keys checks read. */
function onboard(overrides: Json = {}): Json {
  const base: Json = {
    version: 3,
    isolation: {},
    agents: { defaults: { workspace: '~/.picoclaw/workspace', restrict_to_workspace: true, model_name: 'glm-4.7' } },
    channel_list: {
      telegram: { enabled: false, type: 'telegram', allow_from: [], settings: {} },
      line: { enabled: false, type: 'line', settings: { webhook_host: '0.0.0.0', webhook_port: 18791 } },
      maixcam: { enabled: false, type: 'maixcam', settings: { host: '0.0.0.0', port: 18790 } },
      pico: { enabled: false, type: 'pico', settings: {} },
    },
    gateway: { host: 'localhost', port: 18790 },
    tools: { exec: { enabled: true, enable_deny_patterns: true, allow_remote: true, custom_allow_patterns: [] } },
  };
  return merge(base, overrides);
}

function merge(a: Json, b: Json): Json {
  const out: Json = { ...a };
  for (const [k, v] of Object.entries(b)) {
    out[k] = v && typeof v === 'object' && !Array.isArray(v) && out[k] && typeof out[k] === 'object' && !Array.isArray(out[k])
      ? merge(out[k] as Json, v as Json)
      : v;
  }
  return out;
}

function cfg(data: Json, filePath = CONFIG): ParsedConfig {
  return { raw: JSON.stringify(data, null, 2), format: 'json', filePath, data };
}

function ctx(configs: ParsedConfig[]): ScanContext {
  const installation: AgentInstallation = { agent: 'picoclaw', installDir: '/home/test/.picoclaw', configFiles: configs };
  return { installation, configs, platform: 'linux', fs: new LocalFSProvider() };
}

const byId = (id: string) => picoclawChecks.find(c => c.id === id)!;

describe('PicoClaw checks', () => {
  it('exports PCL-001–007 in the picoclaw category', () => {
    expect(picoclawChecks.map(c => c.id)).toEqual(['PCL-001', 'PCL-002', 'PCL-003', 'PCL-004', 'PCL-005', 'PCL-006', 'PCL-007']);
    for (const c of picoclawChecks) {
      expect(c.category).toBe('picoclaw');
      expect(c.supportedAgents).toEqual(['picoclaw']);
    }
  });

  it('a fresh onboard install passes every check', async () => {
    for (const c of picoclawChecks) {
      const r = await c.run(ctx([cfg(onboard())]));
      expect(r.passed, c.id).toBe(true);
    }
  });

  it('never throws on odd shapes', async () => {
    for (const c of picoclawChecks) {
      const nullCfg = { raw: 'null', format: 'json', filePath: CONFIG, data: null } as unknown as ParsedConfig;
      await expect(c.run(ctx([nullCfg]))).resolves.toBeDefined();
    }
    const odd: Json[] = [
      {}, { agents: null, tools: 'x', channel_list: [] },
      { channel_list: { a: null, b: 7, c: { enabled: true } }, tools: { exec: null, allow_read_paths: ['(', 3] } },
      { tools: { exec: { custom_allow_patterns: ['[', null] } } },
    ];
    for (const data of odd) {
      for (const c of picoclawChecks) {
        await expect(c.run(ctx([cfg(data), cfg({ public: 'yes', allowed_cidrs: 'x' }, LAUNCHER)]))).resolves.toBeDefined();
      }
    }
  });
});

describe('PCL-001 workspace restriction', () => {
  it('flags restrict_to_workspace: false (fixable) and allow_read_outside_workspace', async () => {
    const off = await byId('PCL-001').run(ctx([cfg(onboard({ agents: { defaults: { restrict_to_workspace: false } } }))]));
    expect(off.passed).toBe(false);
    expect(off.fixable).toBe(true);
    const reads = await byId('PCL-001').run(ctx([cfg(onboard({ agents: { defaults: { allow_read_outside_workspace: true } } }))]));
    expect(reads.passed).toBe(false);
    expect(reads.fixable).toBe(false);
  });
});

describe('PCL-002 exec guard', () => {
  it('flags a disabled deny list and catch-all allow patterns, not narrow ones', async () => {
    expect((await byId('PCL-002').run(ctx([cfg(onboard({ tools: { exec: { enable_deny_patterns: false } } }))]))).passed).toBe(false);
    expect((await byId('PCL-002').run(ctx([cfg(onboard({ tools: { exec: { custom_allow_patterns: ['.*'] } } }))]))).passed).toBe(false);
    expect((await byId('PCL-002').run(ctx([cfg(onboard({ tools: { exec: { custom_allow_patterns: ['^git status$'] } } }))]))).passed).toBe(true);
  });

  it('understands Go inline flags in patterns', async () => {
    expect((await byId('PCL-002').run(ctx([cfg(onboard({ tools: { exec: { custom_allow_patterns: ['(?i).*'] } } }))]))).passed).toBe(false);
    expect((await byId('PCL-007').run(ctx([cfg(onboard({ tools: { allow_read_paths: ['(?i)^/'] } }))]))).passed).toBe(false);
  });

  it('ignores a disabled exec tool', async () => {
    const data = onboard({ tools: { exec: { enabled: false, enable_deny_patterns: false } } });
    expect((await byId('PCL-002').run(ctx([cfg(data)]))).passed).toBe(true);
  });
});

describe('PCL-003 open channel', () => {
  it('flags enabled chat channels with empty or "*" allow_from, not listed senders or pico', async () => {
    const open = onboard({ channel_list: { telegram: { enabled: true, allow_from: [] } } });
    const r = await byId('PCL-003').run(ctx([cfg(open)]));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
    const star = onboard({ channel_list: { telegram: { enabled: true, allow_from: ['*'] } } });
    expect((await byId('PCL-003').run(ctx([cfg(star)]))).passed).toBe(false);
    const listed = onboard({ channel_list: { telegram: { enabled: true, allow_from: [123456789] } } });
    expect((await byId('PCL-003').run(ctx([cfg(listed)]))).passed).toBe(true);
    const pico = onboard({ channel_list: { pico: { enabled: true, settings: { token: 't', allow_origins: ['http://localhost:18800'] } } } });
    expect((await byId('PCL-003').run(ctx([cfg(pico)]))).passed).toBe(true);
  });
});

describe('PCL-004 remote exec', () => {
  it('flags exec reachable from an enabled chat channel', async () => {
    const data = onboard({ channel_list: { telegram: { enabled: true, allow_from: ['1'] } } });
    expect((await byId('PCL-004').run(ctx([cfg(data)]))).passed).toBe(false);
    const off = merge(data, { tools: { exec: { allow_remote: false } } });
    expect((await byId('PCL-004').run(ctx([cfg(off)]))).passed).toBe(true);
  });
});

describe('PCL-005 pico websocket', () => {
  it('flags open origins and token-in-query', async () => {
    const data = onboard({ channel_list: { pico: { enabled: true, settings: { token: 't', allow_token_query: true } } } });
    const r = await byId('PCL-005').run(ctx([cfg(data)]));
    expect(r.passed).toBe(false);
    expect(r.evidence).toHaveLength(2);
  });
});

describe('PCL-006 launcher exposure', () => {
  const run = (launcher: Json) => byId('PCL-006').run(ctx([cfg(onboard()), cfg(launcher, LAUNCHER)]));

  it('public launcher without a dashboard password is critical', async () => {
    const r = await run({ port: 18800, public: true, allow_localhost_bypass: true });
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
  });

  it('public + password but no CIDR restriction is a warning; with CIDRs it passes', async () => {
    const hash = '$2a$10$abcdefghijklmnopqrstuv';
    expect((await run({ public: true, dashboard_password_hash: hash })).severity).toBe('warning');
    expect((await run({ public: true, dashboard_password_hash: hash, allowed_cidrs: ['10.0.0.0/24'] })).passed).toBe(true);
  });

  it('default launcher passes; a leftover launcher_token is info', async () => {
    expect((await run({ port: 18800, public: false, allow_localhost_bypass: true })).passed).toBe(true);
    const legacy = await run({ public: false, launcher_token: 'abc' });
    expect(legacy.passed).toBe(false);
    expect(legacy.severity).toBe('info');
  });
});

describe('PCL-007 broad tool paths', () => {
  it('flags patterns reaching credentials; writes are critical', async () => {
    const reads = await byId('PCL-007').run(ctx([cfg(onboard({ tools: { allow_read_paths: ['^/.*'] } }))]));
    expect(reads.passed).toBe(false);
    expect(reads.severity).toBe('warning');
    const writes = await byId('PCL-007').run(ctx([cfg(onboard({ tools: { allow_write_paths: [`^${HOME}/.*`] } }))]));
    expect(writes.severity).toBe('critical');
    const narrow = await byId('PCL-007').run(ctx([cfg(onboard({ tools: { allow_read_paths: ['^/srv/projects/app/'] } }))]));
    expect(narrow.passed).toBe(true);
  });
});

describe('fixes write real schema keys', () => {
  let dir: string | undefined;
  afterEach(async () => { if (dir) await rm(dir, { recursive: true, force: true }); });

  it('PCL-001, PCL-002 and PCL-004 set their keys in config.json', async () => {
    dir = await mkdtemp(join(tmpdir(), 'pcl-fix-'));
    const path = join(dir, 'config.json');
    const data = onboard({
      agents: { defaults: { restrict_to_workspace: false } },
      tools: { exec: { enable_deny_patterns: false } },
      channel_list: { telegram: { enabled: true, allow_from: ['1'] } },
    });
    await writeFile(path, JSON.stringify(data, null, 2));
    const c = ctx([cfg(data, path)]);
    for (const id of ['PCL-001', 'PCL-002', 'PCL-004']) {
      expect((await byId(id).fix!(c)).applied, id).toBe(true);
    }
    const out = JSON.parse(await readFile(path, 'utf-8'));
    expect(out.agents.defaults.restrict_to_workspace).toBe(true);
    expect(out.tools.exec.enable_deny_patterns).toBe(true);
    expect(out.tools.exec.allow_remote).toBe(false);
    expect(Object.keys(out).sort()).toEqual(Object.keys(data).sort());
  });
});
