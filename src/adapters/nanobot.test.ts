import { describe, it, expect, vi } from 'vitest';
import { dirname } from 'node:path';
import type { FSProvider } from '../core/fs-provider.js';
import type { ParsedConfig } from '../core/types.js';
import { nanobotAdapter, nanobotWorkspaceDir } from './nanobot.js';

interface FakeFs {
  files?: Record<string, string>;
  dirs?: string[];
  env?: Record<string, string>;
  links?: Record<string, string>;
  which?: string;
  version?: string;
}

function makeFs(o: FakeFs = {}): FSProvider {
  const files = o.files ?? {};
  const dirs = new Set(o.dirs ?? []);
  const children = (p: string) => [
    ...Object.keys(files).filter(f => dirname(f) === p),
    ...[...dirs].filter(d => dirname(d) === p),
  ].map(f => f.slice(p.length + 1));
  return {
    homedir: () => '/home/test',
    platform: 'linux',
    access: vi.fn(async (p: string) => p in files || dirs.has(p)),
    readFile: vi.fn(async (p: string) => {
      if (p in files) return files[p];
      throw new Error(`ENOENT ${p}`);
    }),
    readdir: vi.fn(async (p: string) => {
      if (!dirs.has(p)) throw new Error(`ENOENT ${p}`);
      return children(p);
    }),
    stat: vi.fn(async (p: string) => ({ mode: 0o100600, isFile: () => p in files, isDirectory: () => dirs.has(p) })),
    readdirEntries: vi.fn(async () => []),
    realpath: vi.fn(async (p: string) => o.links?.[p] ?? p),
    execSync: vi.fn((cmd: string, args: string[]) => {
      if (cmd === 'which' && args[0] === 'nanobot' && o.which) return o.which;
      if (args[0] === '--version' && o.version) return o.version;
      throw new Error('not found');
    }),
    getEnv: vi.fn((k: string) => o.env?.[k]),
  } as unknown as FSProvider;
}

// Trimmed `nanobot onboard` output (nanobot-ai 0.3.x)
const CONFIG = JSON.stringify({
  agents: { defaults: { workspace: '~/.nanobot/workspace', model: 'anthropic/claude-opus-4-5', provider: 'auto' } },
  channels: { sendProgress: true, transcriptionLanguage: null, websocket: { enabled: true } },
  api: { host: '127.0.0.1', port: 8900, apiKey: '' },
  gateway: { host: '127.0.0.1', port: 18790, heartbeat: { enabled: true, intervalS: 1800 } },
  tools: { restrictToWorkspace: false },
});

const VENV = '/home/test/.local/share/uv/tools/nanobot-ai';

describe('Nanobot adapter', () => {
  it('returns nothing when neither config nor CLI exists', async () => {
    expect(await nanobotAdapter.detect({ fs: makeFs() })).toEqual([]);
  });

  it('detects ~/.nanobot/config.json with the CLI version from `nanobot --version`', async () => {
    const fs = makeFs({
      dirs: ['/home/test/.nanobot'],
      files: {
        '/home/test/.nanobot/config.json': CONFIG,
        '/home/test/.local/bin/nanobot': '',
      },
      which: '/home/test/.local/bin/nanobot',
      version: '🐈 nanobot v0.3.5',
    });
    const [inst] = await nanobotAdapter.detect({ fs });
    expect(inst.agent).toBe('nanobot');
    expect(inst.installDir).toBe('/home/test/.nanobot');
    expect(inst.configFiles.map(c => c.filePath)).toEqual(['/home/test/.nanobot/config.json']);
    expect(inst.version).toBe('0.3.5');
    expect(inst.cliBinary).toBe('/home/test/.local/bin/nanobot');
    expect(inst.gateway).toEqual({ host: '127.0.0.1', port: 8765, tls: false });
    expect(inst.skillsDir).toBe('/home/test/.nanobot/workspace/skills');
    expect(inst.models).toEqual([{ id: 'claude-opus-4-5', provider: 'anthropic' }]);
  });

  it('falls back to the uv venv dist-info when the CLI cannot be executed', async () => {
    const fs = makeFs({
      dirs: [
        '/home/test/.nanobot',
        `${VENV}/bin`, `${VENV}/lib`, `${VENV}/lib/python3.12`, `${VENV}/lib/python3.12/site-packages`,
        `${VENV}/lib/python3.12/site-packages/nanobot_ai-0.3.5.dist-info`,
      ],
      files: {
        '/home/test/.nanobot/config.json': CONFIG,
        '/home/test/.local/bin/nanobot': '',
        [`${VENV}/bin/nanobot`]: '',
      },
      links: { '/home/test/.local/bin/nanobot': `${VENV}/bin/nanobot` },
      which: '/home/test/.local/bin/nanobot',
    });
    const [inst] = await nanobotAdapter.detect({ fs });
    expect(inst.version).toBe('0.3.5');
  });

  it('does not read npm package.json versions (the npm `nanobot` package is unrelated)', async () => {
    const fs = makeFs({
      dirs: ['/home/test/.nanobot'],
      files: {
        '/home/test/.nanobot/config.json': CONFIG,
        '/usr/local/lib/node_modules/nanobot/package.json': '{"name":"nanobot","version":"0.0.1"}',
      },
    });
    const [inst] = await nanobotAdapter.detect({ fs });
    expect(inst.version).toBeUndefined();
  });

  it('follows a relocated workspace for skills', async () => {
    const cfg = JSON.stringify({ agents: { defaults: { workspace: '/srv/bot-ws' } } });
    const fs = makeFs({
      dirs: ['/home/test/.nanobot', '/srv/bot-ws/plugins'],
      files: { '/home/test/.nanobot/config.json': cfg },
    });
    const [inst] = await nanobotAdapter.detect({ fs });
    expect(inst.skillsDirs).toEqual(['/srv/bot-ws/skills', '/srv/bot-ws/plugins']);
  });

  it('resolves the workspace: config, ~ expansion, ${VAR}, env fallback, default', () => {
    const fs = makeFs({ env: { BOT_WS: '/data/ws', NANOBOT_AGENTS__DEFAULTS__WORKSPACE: '/env/ws' } });
    const dir = '/home/test/.nanobot';
    expect(nanobotWorkspaceDir(dir, { agents: { defaults: { workspace: '~/.nanobot/workspace' } } }, fs))
      .toBe('/home/test/.nanobot/workspace');
    expect(nanobotWorkspaceDir(dir, { agents: { defaults: { workspace: '${BOT_WS}/main' } } }, fs))
      .toBe('/data/ws/main');
    expect(nanobotWorkspaceDir(dir, {}, fs)).toBe('/env/ws');
    expect(nanobotWorkspaceDir(dir, { agents: null } as unknown as Record<string, unknown>, makeFs()))
      .toBe('/home/test/.nanobot/workspace');
  });

  it('reports the websocket channel as the gateway, not the health-only gateway.host (g5-F2)', () => {
    expect(nanobotAdapter.getGatewayInfo({})).toEqual({ host: '127.0.0.1', port: 8765, tls: false });
    // gateway.host serves GET /health only
    expect(nanobotAdapter.getGatewayInfo({ gateway: { host: '0.0.0.0', port: 9000 } }))
      .toEqual({ host: '127.0.0.1', port: 8765, tls: false });
    expect(nanobotAdapter.getGatewayInfo({ channels: { websocket: { host: '0.0.0.0', port: 9001, token: 't' } } }))
      .toEqual({ host: '0.0.0.0', port: 9001, tls: false });
    expect(nanobotAdapter.getGatewayInfo({ channels: { websocket: { unix_socket_path: '/run/nb.sock' } } })).toBeUndefined();
    expect(nanobotAdapter.getGatewayInfo({ channels: { websocket: { enabled: false } } })).toBeUndefined();
    // Top-level host/port are not nanobot keys
    expect(nanobotAdapter.getGatewayInfo({ host: '0.0.0.0', port: 1 })).toEqual({ host: '127.0.0.1', port: 8765, tls: false });
  });

  it('reports wss:// only when sslCertfile and sslKeyfile are both set, in either casing (dt20 g5-F2)', () => {
    const gw = (ws: Record<string, unknown>) => nanobotAdapter.getGatewayInfo({ channels: { websocket: { host: '0.0.0.0', ...ws } } });
    expect(gw({ sslCertfile: '/etc/c.pem', sslKeyfile: '/etc/k.pem' })?.tls).toBe(true);
    expect(gw({ ssl_certfile: '/etc/c.pem', ssl_keyfile: '/etc/k.pem' })?.tls).toBe(true);
    // One without the other: the channel refuses to start over TLS
    expect(gw({ sslCertfile: '/etc/c.pem' })?.tls).toBe(false);
    expect(gw({ sslCertfile: '/etc/c.pem', sslKeyfile: '  ' })?.tls).toBe(false);
  });

  it('reads a numeric-string websocket port as pydantic does (dt20 re-verify)', () => {
    const gw = (port: unknown) => nanobotAdapter.getGatewayInfo({ channels: { websocket: { host: '0.0.0.0', port } } });
    expect(gw('9000')?.port).toBe(9000);
    expect(gw(' 9001 ')?.port).toBe(9001);
    expect(gw('auto')?.port).toBe(8765);
  });

  it('declares credential stores under the data dir', () => {
    const paths = nanobotAdapter.getCredentialPaths!('/home/test/.nanobot');
    expect(paths).toEqual(expect.arrayContaining([
      '/home/test/.nanobot/config.json',
      '/home/test/.nanobot/pairing.json',
      '/home/test/.nanobot/auth/mcp.json',
      '/home/test/.nanobot/auth/xai.json',
    ]));
  });

  it('ships chat history, memory and credentials as metadata only in the probe manifest', () => {
    const m = nanobotAdapter.getProbeManifest!();
    const content = [...m.filePaths, ...m.globPatterns];
    for (const p of content) {
      expect(p).not.toMatch(/sessions|memory|auth|pairing|history|\.md$/);
    }
    expect(m.metadataGlobPatterns).toEqual(expect.arrayContaining([
      '~/.nanobot/sessions/*/*',
      '~/.nanobot/workspace/memory/*',
      '~/.nanobot/auth/*',
      '~/.nanobot/pairing.json',
    ]));
    // No npm paths: the npm `nanobot` package is a different project
    expect(JSON.stringify(m)).not.toContain('node_modules');
  });

  it('getModels: active preset, other presets and inline fallbacks', () => {
    const configs: ParsedConfig[] = [{
      filePath: '/home/test/.nanobot/config.json',
      format: 'json',
      raw: '',
      data: {
        agents: {
          defaults: {
            model: 'anthropic/claude-opus-4-5',
            modelPreset: 'fast',
            fallbackModels: ['deep', { model: 'gpt-4o-mini', provider: 'openai' }],
          },
        },
        modelPresets: {
          fast: { model: 'deepseek/deepseek-chat', provider: 'auto' },
          deep: { model: 'anthropic/claude-sonnet-4-5', provider: 'openrouter' },
        },
      },
    }];
    expect(nanobotAdapter.getModels!(configs)).toEqual([
      { id: 'deepseek-chat', provider: 'deepseek' },
      { id: 'anthropic/claude-sonnet-4-5', provider: 'openrouter', via: 'preset:deep' },
      { id: 'gpt-4o-mini', provider: 'openai', via: 'fallback' },
    ]);
  });
});
