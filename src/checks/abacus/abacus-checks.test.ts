import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { abacusChecks } from './index.js';

const HOME = '/home/test';

function cfg(filePath: string, data: Record<string, unknown>): ParsedConfig {
  return { raw: '', format: 'json', filePath, data };
}

interface FsOpts {
  files?: Record<string, string>;
  modes?: Record<string, number>;
  env?: Record<string, string>;
  dirEntries?: Record<string, string[]>;
}

function makeFs({ files = {}, modes = {}, env = {}, dirEntries = {} }: FsOpts = {}): FSProvider {
  const exists = (p: string) => p in files || p in modes || p in dirEntries;
  return {
    platform: 'linux',
    homedir: () => HOME,
    getEnv: (k: string) => env[k],
    access: vi.fn(async (p: string) => exists(p)),
    readFile: vi.fn(async (p: string) => {
      if (!(p in files)) throw new Error(`ENOENT ${p}`);
      return files[p];
    }),
    stat: vi.fn(async (p: string) => {
      if (!(p in modes)) throw new Error(`ENOENT ${p}`);
      return { mode: modes[p], isFile: () => true, isDirectory: () => false };
    }),
    readdirEntries: vi.fn(async (d: string) => (dirEntries[d] ?? []).map(name => ({ name, isDirectory: false, isFile: true }))),
  } as unknown as FSProvider;
}

function userCtx(configs: ParsedConfig[], fs: FSProvider = makeFs()): ScanContext {
  const installation: AgentInstallation = { agent: 'abacus', installDir: `${HOME}/.abacusai`, configFiles: configs };
  return { installation, configs, platform: 'linux', fs };
}

function projectCtx(configs: ParsedConfig[], fs: FSProvider = makeFs()): ScanContext {
  const installation: AgentInstallation = { agent: 'abacus', installDir: '/work/app/.abacusai', configFiles: configs, profile: 'project' };
  return { installation, configs, platform: 'linux', fs };
}

const check = (id: string) => abacusChecks.find(c => c.id === id)!;
const USER_CFG = `${HOME}/.abacusai/config.json`;
const USER_MCP = `${HOME}/.abacusai/mcp.json`;

describe('Abacus.AI checks', () => {
  it('exports 15 coding-agent checks scoped to abacus', () => {
    expect(abacusChecks).toHaveLength(15);
    for (const c of abacusChecks) {
      expect(c.id).toMatch(/^ABA-0(0[1-9]|1[0-5])$/);
      expect(c.category).toBe('coding-agent');
      expect(c.supportedAgents).toEqual(['abacus']);
    }
  });
});

describe('ABA-001 permission mode', () => {
  it('fails critical on unsupervised and its aliases', async () => {
    for (const mode of ['unsupervised', 'YOLO', 'bypassPermissions']) {
      const r = await check('ABA-001').run(userCtx([cfg(USER_CFG, { permissionMode: mode })]));
      expect(r.passed, mode).toBe(false);
      expect(r.severity).toBe('critical');
      expect(r.fixable).toBe(true);
    }
  });

  it('passes the documented default auto mode and supervise / accept-edits', async () => {
    for (const mode of ['auto', 'supervise', 'accept-edits', 'plan', 'dont-ask']) {
      expect((await check('ABA-001').run(userCtx([cfg(USER_CFG, { permissionMode: mode })]))).passed).toBe(true);
    }
  });

  it('reads the desktop agent-config and the ABACUS_PERMISSION_MODE override', async () => {
    const desktop = cfg(`${HOME}/.abacusai/desktop/agent-config-code.json`, { permissionMode: 'unsupervised' });
    expect((await check('ABA-001').run(userCtx([desktop]))).passed).toBe(false);
    const env = await check('ABA-001').run(userCtx([], makeFs({ env: { ABACUS_PERMISSION_MODE: 'yolo' } })));
    expect(env.passed).toBe(false);
    expect(env.evidence?.[0].file).toBe('<process env>');
  });

  it('downgrades a project setting in an untrusted workspace and keeps it live once trusted', async () => {
    const project = cfg('/work/app/.abacusai/config.json', { permissionMode: 'unsupervised' });
    const untrusted = await check('ABA-001').run(projectCtx([project]));
    expect(untrusted.passed).toBe(false);
    expect(untrusted.severity).toBe('info');
    expect(untrusted.evidence?.[0].detail).toMatch(/inactive until workspace "app" is trusted/);

    const trustFile = `${HOME}/.abacusai/trusted-workspaces.json`;
    const fs = makeFs({ files: { [trustFile]: JSON.stringify({ workspaces: { '/work/app': { trustedAt: '2026-10-05' } } }) } });
    expect((await check('ABA-001').run(projectCtx([project], fs))).severity).toBe('critical');
    const parentTrust = makeFs({ files: { [trustFile]: JSON.stringify({ workspaces: { '/work': { trustedAt: 'x' } } }) } });
    expect((await check('ABA-001').run(projectCtx([project], parentTrust))).severity).toBe('critical');
    const siblingTrust = makeFs({ files: { [trustFile]: JSON.stringify({ workspaces: { '/work/ap': { trustedAt: 'x' } } }) } });
    expect((await check('ABA-001').run(projectCtx([project], siblingTrust))).severity).toBe('info');
    const envTrust = makeFs({ env: { ABACUS_TRUST_WORKSPACE: 'true' } });
    expect((await check('ABA-001').run(projectCtx([project], envTrust))).severity).toBe('critical');
  });

  it('does not offer a fix when the only evidence is an inactive untrusted-project setting', async () => {
    const r = await check('ABA-001').run(projectCtx([cfg('/work/app/.abacusai/config.json', { permissionMode: 'unsupervised' })]));
    expect(r.passed).toBe(false);
    expect(r.fixable).toBe(false);
  });
});

describe('ABA-002 broad permission rules', () => {
  it('flags unrestricted Bash and whole-disk / credential writes as critical', async () => {
    const r = await check('ABA-002').run(userCtx([cfg(USER_CFG, {
      permissions: { allow: ['Bash', 'Bash(*)', 'Edit(//**)', 'Write(~/.ssh/**)', 'Edit(src/**)', 'Bash(git log *)'] },
    })]));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
    expect(r.evidence).toHaveLength(4);
  });

  it('warns on wildcard shells and network tools only', async () => {
    const r = await check('ABA-002').run(userCtx([cfg(USER_CFG, { permissions: { allow: ['Bash(curl *)', 'Bash(npm test)'] } })]));
    expect(r.severity).toBe('warning');
    expect(r.evidence).toHaveLength(1);
  });

  it('treats an all-wildcard Bash pattern as any command and /private/etc as /etc', async () => {
    const r0 = await check('ABA-002').run(userCtx([cfg(USER_CFG, { permissions: { allow: ['Bash(* *)'] } })]));
    expect(r0.severity).toBe('critical');
    const etc = await check('ABA-002').run(userCtx([cfg(USER_CFG, { permissions: { allow: ['Write(//private/etc/**)'] } })]));
    expect(etc.severity).toBe('critical');
  });

  it('treats /path, ./path and path as workspace-anchored and // as the filesystem root', async () => {
    const workspace = await check('ABA-002').run(userCtx([cfg(USER_CFG, {
      permissions: { allow: ['Edit(/**)', 'Edit(/etc/**)', 'Write(/src/**)', 'Edit(./.ssh/**)', 'Write(.aws/**)'] },
    })]));
    expect(workspace.passed).toBe(true);
    const root = await check('ABA-002').run(userCtx([cfg(USER_CFG, { permissions: { allow: ['Edit(//etc/**)', 'Write(~/**)'] } })]));
    expect(root.severity).toBe('critical');
    expect(root.evidence).toHaveLength(2);
  });

  it('passes scoped rules', async () => {
    const r = await check('ABA-002').run(userCtx([cfg(USER_CFG, { permissions: { allow: ['Read', 'Edit', 'Bash(git status)'], deny: ['Bash(rm *)'] } })]));
    expect(r.passed).toBe(true);
  });
});

describe('ABA-003 credential store permissions', () => {
  it('fails critical on a group-readable keystore and warns on desktop key stores', async () => {
    const fs = makeFs({ modes: {
      [`${HOME}/.abacusai/keystore.enc`]: 0o644,
      [`${HOME}/.config/AbacusAI Desktop/provider-keys.json`]: 0o666,
      [HOME]: 0o755, [`${HOME}/.abacusai`]: 0o755, [`${HOME}/.config`]: 0o755, [`${HOME}/.config/AbacusAI Desktop`]: 0o755, '/home': 0o755, '/': 0o755,
    } });
    const r = await check('ABA-003').run(userCtx([], fs));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
    expect(r.evidence).toHaveLength(2);
  });

  it('downgrades when the parent directory blocks access', async () => {
    const fs = makeFs({ modes: {
      [`${HOME}/.config/AbacusAI Desktop/provider-keys.json`]: 0o666,
      [`${HOME}/.config/AbacusAI Desktop`]: 0o700, [`${HOME}/.config`]: 0o755, [HOME]: 0o755, '/home': 0o755, '/': 0o755,
    } });
    const r = await check('ABA-003').run(userCtx([], fs));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('info');
  });

  it('passes on a 0600 keystore and skips project installs', async () => {
    const fs = makeFs({ modes: { [`${HOME}/.abacusai/keystore.enc`]: 0o600 } });
    expect((await check('ABA-003').run(userCtx([], fs))).passed).toBe(true);
    expect((await check('ABA-003').run(projectCtx([]))).passed).toBe(true);
  });
});

describe('MCP checks (ABA-004/006/007/008) over both config shapes', () => {
  const mapShape = cfg(USER_MCP, { mcpServers: {
    gh: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'], env: { GITHUB_TOKEN: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij' } },
    remote: { type: 'http', url: 'http://mcp.example.com/mcp', headers: { Authorization: 'Bearer abcdefghijklmnop' }, autoApprove: true },
    local: { type: 'http', url: 'http://127.0.0.1:8080/mcp' },
    off: { command: 'npx', args: ['evil-server'], disabled: true },
  } });
  const arrayShape = cfg(USER_CFG, { mcpServers: [
    { name: 'db', command: 'uvx', args: ['mcp-server-sqlite'], env: { DB_PASSWORD: 'hunter2hunter2' } },
    { name: 'pinned', command: 'npx', args: ['@scope/srv@1.2.3'], env: { HOME_DIR: '/home/test' } },
  ] });

  it('ABA-004 flags literal secrets in env and headers, not disabled servers or plain values', async () => {
    const r = await check('ABA-004').run(userCtx([mapShape, arrayShape]));
    expect(r.passed).toBe(false);
    expect(r.evidence?.map(e => e.snippet?.split(':')[0])).toEqual([
      'mcpServers.gh.env.GITHUB_TOKEN',
      'mcpServers.remote.headers.Authorization',
      'mcpServers[db].env.DB_PASSWORD',
    ]);
  });

  it('ABA-004 ignores environment references', async () => {
    const r = await check('ABA-004').run(userCtx([cfg(USER_MCP, { mcpServers: {
      a: { command: 'x', env: { API_KEY: '${API_KEY}' } },
      b: { type: 'http', url: 'https://mcp.example.com/mcp', headers: { Authorization: 'Bearer ${MCP_TOKEN}', 'X-Api-Key': '$KEY' } },
    } })]));
    expect(r.passed).toBe(true);
  });

  it('ABA-004 does not report URLs, paths or mode words under auth-ish names', async () => {
    const r = await check('ABA-004').run(userCtx([cfg(USER_MCP, { mcpServers: {
      a: { command: 'x', env: {
        AUTH_MODE: 'oauth-device', GITHUB_API_URL: 'https://api.github.com', SESSION_DIR: '/var/tmp/sessions',
        API_KEY_FILE: '~/.config/key', TOKEN_ENV: 'GITHUB_TOKEN', API_VERSION: '2024-10-01',
        SESSION_SECRET_SEED: 'q8Zr2LmW7xVb4NcT', API_ACCESS: 'Xk29fLq8Zr2mW7vB',
      } },
    } })]));
    // Only the secret-named key and the credential-shaped API_ACCESS value count
    expect(r.evidence?.map(e => e.snippet?.split(':')[0])).toEqual([
      'mcpServers.a.env.SESSION_SECRET_SEED',
      'mcpServers.a.env.API_ACCESS',
    ]);
  });

  it('ABA-006 flags unpinned runners in both shapes', async () => {
    const r = await check('ABA-006').run(userCtx([mapShape, arrayShape]));
    expect(r.evidence).toHaveLength(2);
  });

  it('ABA-007 flags non-loopback http only', async () => {
    const r = await check('ABA-007').run(userCtx([mapShape]));
    expect(r.evidence).toHaveLength(1);
    expect(r.evidence?.[0].snippet).toContain('mcp.example.com');
  });

  it('ABA-008 ignores MCP-file autoApprove lists, which Abacus.AI does not honour', async () => {
    expect((await check('ABA-008').run(userCtx([mapShape]))).passed).toBe(true);
  });

  it('ABA-008 flags allow rules covering every tool of an MCP server, not tool-scoped rules', async () => {
    const r = await check('ABA-008').run(userCtx([cfg(USER_CFG, { permissions: {
      allow: ['mcp__github', 'mcp__playwright__*', 'mcp__*', 'mcp__github__get_*', 'mcp__github__create_issue', 'Bash(git log *)'],
    } })]));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('warning');
    expect(r.evidence?.map(e => e.snippet)).toEqual([
      'permissions.allow: "mcp__github"',
      'permissions.allow: "mcp__playwright__*"',
      'permissions.allow: "mcp__*"',
    ]);
  });

  it('ABA-008 downgrades rules from an untrusted project', async () => {
    const r = await check('ABA-008').run(projectCtx([cfg('/work/app/.abacusai/config.json', { permissions: { allow: ['mcp__github'] } })]));
    expect(r.severity).toBe('info');
  });

  it('ABA-004 ignores documentation placeholders in an OAuth client secret, not a literal one', async () => {
    const placeholder = await check('ABA-004').run(userCtx([cfg(USER_MCP, { mcpServers: {
      a: { url: 'https://mcp.example.com/mcp', oauth: { clientId: 'abacus-agent', clientSecret: '<only if your provider issued one>' } },
      b: { url: 'https://mcp.example.com/mcp', oauth: { clientId: 'x', clientSecret: '${OAUTH_SECRET}' } },
      c: { url: 'https://mcp.example.com/mcp', oauth: { clientId: 'x', clientSecret: 'your-client-secret' } },
    } })]));
    expect(placeholder.passed).toBe(true);
    const literal = await check('ABA-004').run(userCtx([cfg(USER_MCP, { mcpServers: {
      a: { url: 'https://mcp.example.com/mcp', oauth: { clientId: 'x', clientSecret: 'supersecretvalue123' } },
    } })]));
    expect(literal.passed).toBe(false);
  });
});

describe('ABA-005 provider API keys', () => {
  it('flags literal keys and accepts apiKeyEnvVar', async () => {
    const r = await check('ABA-005').run(userCtx([cfg(USER_CFG, { providers: {
      openai: { npm: '@ai-sdk/openai', options: { apiKey: 'sk-proj-abcdefghijklmnopqrstuvwxyz' } },
      ollama: { npm: '@ai-sdk/openai-compatible', apiKeyEnvVar: 'OLLAMA_KEY', options: { baseURL: 'http://localhost:11434/v1' } },
    } })]));
    expect(r.passed).toBe(false);
    expect(r.evidence).toHaveLength(1);
  });
});

describe('ABA-005 provider request headers', () => {
  it('flags a literal Authorization header and ignores env references', async () => {
    const r = await check('ABA-005').run(userCtx([cfg(USER_CFG, { providers: {
      gw: { options: { baseURL: 'https://gw.example.com/v1', headers: { Authorization: 'Bearer q8Zr2LmW7xVb4NcTk3Yd', 'X-Title': 'my-app' } } },
      ok: { options: { headers: { Authorization: 'Bearer ${GW_TOKEN}' } } },
    } })]));
    expect(r.evidence?.map(e => e.snippet?.split(':')[0])).toEqual(['providers.gw.options.headers.Authorization']);
  });
});

describe('ABA-009 workspace trust', () => {
  it('flags ABACUS_TRUST_WORKSPACE and a home-wide trusted workspace', async () => {
    const trustFile = `${HOME}/.abacusai/trusted-workspaces.json`;
    const fs = makeFs({
      env: { ABACUS_TRUST_WORKSPACE: '1' },
      files: { [trustFile]: JSON.stringify({ workspaces: { [HOME]: { trustedAt: 'x' }, '/work/app': { trustedAt: 'y' } } }) },
    });
    const r = await check('ABA-009').run(userCtx([], fs));
    expect(r.passed).toBe(false);
    expect(r.evidence).toHaveLength(2);
  });

  it('passes with scoped trust', async () => {
    expect((await check('ABA-009').run(userCtx([]))).passed).toBe(true);
  });
});

describe('ABA-010 external MCP configs', () => {
  it('flags loadExternalMcpConfigs and offers a fix', async () => {
    const r = await check('ABA-010').run(userCtx([cfg(USER_CFG, { loadExternalMcpConfigs: true })]));
    expect(r.passed).toBe(false);
    expect(r.fixable).toBe(true);
    expect((await check('ABA-010').run(userCtx([cfg(USER_CFG, { loadExternalMcpConfigs: false })]))).passed).toBe(true);
  });

  it('does not offer a fix for an untrusted project setting', async () => {
    const r = await check('ABA-010').run(projectCtx([cfg('/work/app/.abacusai/config.json', { loadExternalMcpConfigs: true })]));
    expect(r.passed).toBe(false);
    expect(r.fixable).toBe(false);
  });
});

describe('ABA-011 API endpoints', () => {
  it('fails critical on an http baseUrl and warns on a non-abacus host', async () => {
    const http = await check('ABA-011').run(userCtx([cfg(USER_CFG, { baseUrl: 'http://proxy.corp.example:8080' })]));
    expect(http.severity).toBe('critical');
    const other = await check('ABA-011').run(userCtx([cfg(USER_CFG, { baseUrl: 'https://llm-gw.example.com' })]));
    expect(other.severity).toBe('warning');
    expect((await check('ABA-011').run(userCtx([cfg(USER_CFG, { baseUrl: 'https://apps.abacus.ai' })]))).passed).toBe(true);
    expect((await check('ABA-011').run(userCtx([cfg(USER_CFG, { baseUrl: 'https://localhost:8443/v1' })]))).passed).toBe(true);
    // Host anchored: a domain that merely starts with "localhost" is remote
    const lookalike = await check('ABA-011').run(userCtx([cfg(USER_CFG, { baseUrl: 'https://localhost.evil.example' })]));
    expect(lookalike.severity).toBe('warning');
  });

  it('flags a plaintext non-loopback provider endpoint', async () => {
    const r = await check('ABA-011').run(userCtx([cfg(USER_CFG, { providers: { lan: { options: { baseURL: 'http://10.0.0.5:8000/v1' } } } })]));
    expect(r.passed).toBe(false);
  });
});

describe('ABA-012 AGENTS.md secrets', () => {
  it('scans the workspace AGENTS.md for project installs', async () => {
    const fs = makeFs({ files: { '/work/app/AGENTS.md': 'deploy with AKIAZ7QX4M2PLR5TNW3B\n' } });
    const r = await check('ABA-012').run(projectCtx([], fs));
    expect(r.passed).toBe(false);
  });

  it('passes when no AGENTS.md exists', async () => {
    expect((await check('ABA-012').run(projectCtx([]))).passed).toBe(true);
  });

  // dt20 g6-F4: keyed credentials in prose
  it('flags a keyed credential the entropy scan cannot see', async () => {
    const fs = makeFs({ files: { '/work/app/AGENTS.md': '# Deploy\nDB_PASSWORD=Pq7Wz2Lk9Xv4Rt8Ns3Jm6Hb1\n' } });
    const r = await check('ABA-012').run(projectCtx([], fs));
    expect(r.passed).toBe(false);
    expect(r.evidence?.[0].snippet).toBe('DB_PASSWORD: <literal, 24 chars>');
  });
});

describe('ABA-013 additional directories', () => {
  it('flags home, credential dirs and temp dirs', async () => {
    const r = await check('ABA-013').run(userCtx([cfg(USER_CFG, { additionalDirectories: ['~', '~/.aws', '/tmp', '/work/other'] })]));
    expect(r.severity).toBe('critical');
    expect(r.evidence).toHaveLength(3);
  });
});

describe('ABA-013 macOS /private paths', () => {
  it('judges /private/etc like /etc', async () => {
    const etc = await check('ABA-013').run(userCtx([cfg(USER_CFG, { additionalDirectories: ['/etc'] })]));
    const priv = await check('ABA-013').run(userCtx([cfg(USER_CFG, { additionalDirectories: ['/private/etc'] })]));
    expect(etc.passed).toBe(false);
    expect(priv.passed).toBe(false);
    expect(priv.severity).toBe(etc.severity);
  });
});

describe('ABA-014 updates', () => {
  it('warns when updates are off and notes pre-release channels', async () => {
    expect((await check('ABA-014').run(userCtx([cfg(USER_CFG, { autoUpdate: 'off' })]))).severity).toBe('warning');
    const canary = await check('ABA-014').run(userCtx([cfg(USER_CFG, { updateChannel: 'canary' })]));
    expect(canary.passed).toBe(false);
    expect(canary.severity).toBe('info');
    expect((await check('ABA-014').run(userCtx([cfg(USER_CFG, { autoUpdate: 'prompt' })]))).passed).toBe(true);
  });
});

describe('ABA-015 state permissions', () => {
  it('fails critical on a world-writable binary directory', async () => {
    const fs = makeFs({ modes: { [`${HOME}/.abacusai/bin`]: 0o777, [`${HOME}/.abacusai`]: 0o755, [HOME]: 0o755, '/home': 0o755, '/': 0o755 } });
    const r = await check('ABA-015').run(userCtx([], fs));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
  });

  it('does not flag the installer default 0775 dirs as world-writable, and downgrades world-readable logs behind a 0750 home', async () => {
    const fs = makeFs({ modes: {
      [`${HOME}/.abacusai`]: 0o775, [`${HOME}/.abacusai/bin`]: 0o775, [`${HOME}/.abacusai/logs`]: 0o775,
      [HOME]: 0o750, '/home': 0o755, '/': 0o755,
    } });
    const r = await check('ABA-015').run(userCtx([], fs));
    expect(r.evidence?.map(e => e.file)).toEqual([`${HOME}/.abacusai/logs`]);
    expect(r.severity).toBe('info');
  });

  it('flags a world-readable prompt history', async () => {
    const fs = makeFs({ modes: { [`${HOME}/.abacusai/history.jsonl`]: 0o644, [`${HOME}/.abacusai`]: 0o755, [HOME]: 0o755, '/home': 0o755, '/': 0o755 } });
    const r = await check('ABA-015').run(userCtx([], fs));
    expect(r.evidence?.map(e => e.file)).toEqual([`${HOME}/.abacusai/history.jsonl`]);
    expect(r.severity).toBe('warning');
  });

  it('flags world-writable desktop state but leaves key stores to ABA-003', async () => {
    const desktop = `${HOME}/.config/AbacusAI Desktop`;
    const fs = makeFs({
      modes: { [`${desktop}/local-code.json`]: 0o666, [`${desktop}/provider-keys.json`]: 0o666, [desktop]: 0o700, [`${HOME}/.config`]: 0o755, [HOME]: 0o755, '/home': 0o755, '/': 0o755 },
      dirEntries: { [desktop]: ['local-code.json', 'provider-keys.json'] },
    });
    const r = await check('ABA-015').run(userCtx([], fs));
    expect(r.evidence).toHaveLength(1);
    expect(r.severity).toBe('info'); // 0700 parent blocks other users
  });
});
