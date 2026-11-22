import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, rm, chmod, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { cfg001 } from './cfg-001-gateway-binding.js';
import { cfg002 } from './cfg-002-api-key-exposure.js';
import { cfg003 } from './cfg-003-file-permissions.js';
import { cfg004 } from './cfg-004-tls-config.js';
import { cfg005 } from './cfg-005-shell-allowlist.js';
import { cfg006 } from './cfg-006-workspace-restriction.js';
import { cfg007 } from './cfg-007-webhook-auth.js';
import { cfg008 } from './cfg-008-sandbox-disabled.js';
import { cfg009 } from './cfg-009-default-credentials.js';
import { cfg010 } from './cfg-010-rate-limiting.js';
import { cfg011 } from './cfg-011-node-cve.js';
import { cfg012 } from './cfg-012-auth-bypass.js';
import { cfg013 } from './cfg-013-dm-policy.js';
import { cfg014 } from './cfg-014-tool-policy.js';
import { cfg015 } from './cfg-015-mdns-broadcast.js';

function makeConfig(data: Record<string, unknown>, raw?: string): ParsedConfig {
  return {
    raw: raw ?? JSON.stringify(data, null, 2),
    format: 'json',
    filePath: '/tmp/test-config.json',
    data,
  };
}

function makeContext(configs: ParsedConfig[], agent: AgentInstallation['agent'] = 'openclaw'): ScanContext {
  const installation: AgentInstallation = {
    agent,
    installDir: '/tmp/test-openclaw',
    configFiles: configs,
    gateway: configs.length > 0
      ? {
          host: (configs[0].data.gateway as Record<string, unknown>)?.host as string,
          port: (configs[0].data.gateway as Record<string, unknown>)?.port as number,
          tls: (configs[0].data.gateway as Record<string, unknown>)?.tls as boolean,
        }
      : undefined,
  };
  return { installation, configs, platform: 'darwin', fs: new LocalFSProvider() };
}

describe('CFG-001: Gateway Binding', () => {
  it('fails when gateway bound to 0.0.0.0', async () => {
    const config = makeConfig({ gateway: { host: '0.0.0.0', port: 18789 } });
    const result = await cfg001.run(makeContext([config]));
    console.log(`[CFG-001] host=0.0.0.0 → passed: ${result.passed}, severity: ${result.severity}, message: ${result.message}`);
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('passes when gateway bound to 127.0.0.1', async () => {
    const config = makeConfig({ gateway: { host: '127.0.0.1', port: 18789 } });
    const result = await cfg001.run(makeContext([config]));
    console.log(`[CFG-001] host=127.0.0.1 → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(true);
  });

  it('ignores wildcard listeners in disabled sections (config templates)', async () => {
    const data = {
      gateway: { host: 'localhost', port: 18790 },
      channel_list: { line: { enabled: false, settings: { webhook_host: '0.0.0.0' } } },
    };
    const raw = JSON.stringify(data, null, 2);
    const result = await cfg001.run(makeContext([makeConfig(data, raw)]));
    expect(result.passed).toBe(true);
  });

  it('flags a wildcard listener in an enabled section', async () => {
    const data = { channels: { msteams: { enabled: true, host: '0.0.0.0', port: 3978 } } };
    const raw = JSON.stringify(data, null, 2);
    const result = await cfg001.run(makeContext([makeConfig(data, raw)]));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].detail).toContain('channels.msteams.host');
    expect(result.evidence?.[0].line).toBeGreaterThan(0);
  });

  it.each(['*', 'localhost,0.0.0.0'])('flags gateway.host %s', async (host) => {
    const data = { gateway: { host } };
    expect((await cfg001.run(makeContext([makeConfig(data, JSON.stringify(data))]))).passed).toBe(false);
  });

  it('still reports a wildcard server.host / host when gateway.host is loopback', async () => {
    for (const data of [{ gateway: { host: '127.0.0.1' }, server: { host: '0.0.0.0' } }, { gateway: { host: '127.0.0.1' }, host: '0.0.0.0' }]) {
      const r = await cfg001.run(makeContext([makeConfig(data, JSON.stringify(data, null, 2))]));
      expect(r.passed, JSON.stringify(data)).toBe(false);
    }
  });

  it('reports gateway.host once', async () => {
    const data = { gateway: { host: '0.0.0.0' } };
    const result = await cfg001.run(makeContext([makeConfig(data, JSON.stringify(data, null, 2))]));
    expect(result.evidence).toHaveLength(1);
  });

  it('passes with no gateway config', async () => {
    const config = makeConfig({});
    const result = await cfg001.run(makeContext([config]));
    console.log(`[CFG-001] no gateway → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(true);
  });
});

describe('CFG-002: API Key Exposure', () => {
  it('fails when API key found in config', async () => {
    const raw = '{\n  "apiKey": "sk-abc123456789012345678901234567890123"\n}';
    const config = makeConfig({ apiKey: 'sk-abc123456789012345678901234567890123' }, raw);
    const result = await cfg002.run(makeContext([config]));
    console.log(`[CFG-002] sk-* key in config → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(false);
  });

  it('passes on documentation placeholders (sk-ant-your-actual-…-here, AWS EXAMPLE keys)', async () => {
    const raw = '{\n  "ANTHROPIC_API_KEY": "sk-ant-your-actual-anthropic-key-here",\n  "aws": "AKIAIOSFODNN7EXAMPLE"\n}';
    const config = makeConfig({ ANTHROPIC_API_KEY: 'sk-ant-your-actual-anthropic-key-here', aws: 'AKIAIOSFODNN7EXAMPLE' }, raw);
    expect((await cfg002.run(makeContext([config]))).passed).toBe(true);
  });

  it('fails when AWS key found', async () => {
    const raw = '{\n  "aws": "AKIAZ7QX4M2PLR5TNW3B"\n}';
    const config = makeConfig({ aws: 'AKIAZ7QX4M2PLR5TNW3B' }, raw);
    const result = await cfg002.run(makeContext([config]));
    console.log(`[CFG-002] AWS key in config → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(false);
  });

  it.each([
    ['sk-proj-' + 'Ab3_d-EfGh'.repeat(4)],
    ['sk-svcacct-' + 'Zy9-xW_vU8'.repeat(4)],
    ['sk-or-v1-' + '0123456789abcdef'.repeat(4)],
  ])('detects current-format provider key %s', async (key) => {
    const raw = `{\n  "apiKey": "${key}"\n}`;
    expect((await cfg002.run(makeContext([makeConfig({ apiKey: key }, raw)]))).passed).toBe(false);
  });

  it('passes with clean config', async () => {
    const config = makeConfig({ gateway: { host: '127.0.0.1' } });
    const result = await cfg002.run(makeContext([config]));
    console.log(`[CFG-002] clean config → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(true);
  });

  it('skips .env files', async () => {
    const envConfig: ParsedConfig = {
      raw: 'API_KEY=sk-abc123456789012345678901234567890123',
      format: 'env',
      filePath: '/tmp/.env',
      data: { API_KEY: 'sk-abc123456789012345678901234567890123' },
    };
    const result = await cfg002.run(makeContext([envConfig]));
    console.log(`[CFG-002] .env file → passed: ${result.passed} (skipped), message: ${result.message}`);
    expect(result.passed).toBe(true);
  });

  it('redacts the matched secret in evidence snippets', async () => {
    const secret = 'sk-ant-AAAAAAAAAAAAAAAAAAAAAAAABBBBCCCC';
    const raw = `{\n  "apiKey": "${secret}"\n}`;
    const config = makeConfig({ apiKey: secret }, raw);
    const result = await cfg002.run(makeContext([config]));

    expect(result.passed).toBe(false);
    expect(result.evidence?.length).toBeGreaterThan(0);
    for (const ev of result.evidence ?? []) {
      expect(ev.snippet).toBeDefined();
      // The full secret must never appear in any evidence snippet.
      expect(ev.snippet).not.toContain(secret);
      // Surrounding context (the JSON key name) should still be preserved
      // so users can identify which credential to rotate.
      expect(ev.snippet).toContain('"apiKey"');
    }
  });

  it('redacts every key in a line containing multiple distinct secrets', async () => {
    const oai = 'sk-AAAAAAAAAAAAAAAAAAAAAAAABBBB';
    const ghp = 'ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB';
    const raw = `{ "openai": "${oai}", "github": "${ghp}" }`;
    const config = makeConfig({ openai: oai, github: ghp }, raw);
    const result = await cfg002.run(makeContext([config]));

    expect(result.passed).toBe(false);
    for (const ev of result.evidence ?? []) {
      expect(ev.snippet).not.toContain(oai);
      expect(ev.snippet).not.toContain(ghp);
    }
  });
});

describe('CFG-003: Credential Config Permissions', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'vaso-cfg003-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  function makeCtxWithCreds(configs: ParsedConfig[], credentialPaths?: string[]): ScanContext {
    const installation: AgentInstallation = {
      agent: 'openclaw',
      installDir: tempDir,
      configFiles: configs,
    };
    return { installation, configs, platform: 'darwin', fs: new LocalFSProvider(), credentialPaths };
  }

  it('skips when adapter does not declare credential paths', async () => {
    const filePath = join(tempDir, 'config.json');
    await writeFile(filePath, '{}');
    await chmod(filePath, 0o644);
    const config: ParsedConfig = { raw: '{}', format: 'json', filePath, data: {} };

    const result = await cfg003.run(makeCtxWithCreds([config]));
    expect(result.passed).toBe(true);
    expect(result.message).toMatch(/does not declare credential paths/i);
  });

  it('does not flag a non-credential config file even if world-readable', async () => {
    // The same parsed config exists on disk with 0644, but the adapter has not
    // declared it as credential-bearing — so CFG-003 must ignore it.
    const benign = join(tempDir, 'preferences.json');
    await writeFile(benign, '{}');
    await chmod(benign, 0o644);
    const config: ParsedConfig = { raw: '{}', format: 'json', filePath: benign, data: {} };

    const credPath = join(tempDir, 'auth.json');
    await writeFile(credPath, '{"token":"abc"}');
    await chmod(credPath, 0o600);
    const credConfig: ParsedConfig = { raw: '{"token":"abc"}', format: 'json', filePath: credPath, data: {} };

    const result = await cfg003.run(makeCtxWithCreds([config, credConfig], [credPath]));
    expect(result.passed).toBe(true);
  });

  it('flags a declared settings file only when it holds a secret (Claude Code settings.json)', async () => {
    const settings = join(tempDir, 'settings.json');
    await writeFile(settings, '{"permissions":{"allow":["Bash(npm test)"]}}');
    await chmod(settings, 0o644);
    const plain: ParsedConfig = { raw: '', format: 'json', filePath: settings, data: { permissions: { allow: ['Bash(npm test)'] } } };
    expect((await cfg003.run(makeCtxWithCreds([plain], [settings]))).passed).toBe(true);
    const withKey: ParsedConfig = { ...plain, data: { env: { ANTHROPIC_API_KEY: 'sk-ant-api03-Ab3dEf6hIj9kLm2nOp5qRs8tUv' } } };
    expect((await cfg003.run(makeCtxWithCreds([withKey], [settings]))).passed).toBe(false);
  });

  it('flags a credential-declared config file with permissive permissions', async () => {
    const credPath = join(tempDir, 'auth.json');
    await writeFile(credPath, '{"token":"abc"}');
    await chmod(credPath, 0o644);
    const credConfig: ParsedConfig = { raw: '{"token":"abc"}', format: 'json', filePath: credPath, data: {} };

    const result = await cfg003.run(makeCtxWithCreds([credConfig], [credPath]));
    expect(result.passed).toBe(false);
    expect(result.evidence!.some(e => e.file === credPath)).toBe(true);
  });
});

describe('CFG-004: TLS Not Configured', () => {
  it('fails when TLS is not configured', async () => {
    const config = makeConfig({ gateway: { host: '0.0.0.0', tls: false } });
    const ctx = makeContext([config]);
    ctx.installation.gateway = { host: '0.0.0.0', tls: false };
    const result = await cfg004.run(ctx);
    console.log(`[CFG-004] tls=false → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(false);
  });

  it('passes when TLS is enabled', async () => {
    const raw = '{"gateway": {"tls": true}}';
    const config = makeConfig({ gateway: { tls: true } }, raw);
    const ctx = makeContext([config]);
    ctx.installation.gateway = { tls: true };
    const result = await cfg004.run(ctx);
    console.log(`[CFG-004] tls=true → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(true);
  });
});

describe('CFG-004: loopback gateways', () => {
  it.each(['127.0.0.1', 'localhost', '::1'])('does not require TLS on %s', async (host) => {
    const ctx = makeContext([makeConfig({ gateway: { host } })]);
    ctx.installation.gateway = { host };
    expect((await cfg004.run(ctx)).passed).toBe(true);
  });
});

// Generic keys apply to plugin adapters; built-in frameworks use their own schemas
const PLUGIN_AGENT = 'plugin-agent' as AgentInstallation['agent'];

describe('CFG-005: Missing Shell Allowlist', () => {
  it('fails when no safeBins configured', async () => {
    const config = makeConfig({});
    const result = await cfg005.run(makeContext([config], PLUGIN_AGENT));
    console.log(`[CFG-005] no safeBins → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(false);
  });

  it('passes when safeBins configured', async () => {
    const config = makeConfig({ security: { safeBins: ['ls', 'cat', 'grep'] } });
    const result = await cfg005.run(makeContext([config], PLUGIN_AGENT));
    console.log(`[CFG-005] safeBins=[ls,cat,grep] → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(true);
  });

  describe('OpenClaw 2026.x exec policy', () => {
    it.each([
      [{}, false, 'OpenClaw default'],
      [{ tools: { exec: { security: 'full' } } }, false, 'tools.exec.security'],
      [{ tools: { exec: { mode: 'full' } } }, false, 'tools.exec.mode'],
      [{ tools: { exec: { mode: 'ask' } } }, true, 'tools.exec.mode'],
      [{ tools: { exec: { security: 'allowlist' } } }, true, 'tools.exec.security'],
      // security.safeBins is not an OpenClaw key: it doesn't restrict anything
      [{ security: { safeBins: ['ls'] } }, false, 'OpenClaw default'],
    ])('%j → passed %s (%s)', async (data, passed, source) => {
      const result = await cfg005.run(makeContext([makeConfig(data)]));
      expect(result.passed).toBe(passed);
      expect(result.message).toContain(source);
      expect(result.fixable).toBeFalsy(); // guidance only: OpenClaw rejects unknown/mixed keys
    });
  });
});

describe('CFG-006: Workspace Restriction', () => {
  it('fails when no workspace configured', async () => {
    const config = makeConfig({});
    const result = await cfg006.run(makeContext([config]));
    console.log(`[CFG-006] no workspace → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(false);
  });

  it('passes when workspace configured (generic schema)', async () => {
    const config = makeConfig({ workspace: '/home/user/projects' });
    const result = await cfg006.run(makeContext([config], 'custom-agent' as AgentInstallation['agent']));
    console.log(`[CFG-006] workspace=/home/user/projects → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(true);
  });
});

describe('CFG-006 on OpenClaw', () => {
  it('reads tools.fs.workspaceOnly, not the workspace location', async () => {
    expect((await cfg006.run(makeContext([makeConfig({ agents: { defaults: { workspace: '~/w' } } })]))).passed).toBe(false);
    expect((await cfg006.run(makeContext([makeConfig({ tools: { fs: { workspaceOnly: true } } })]))).passed).toBe(true);
  });
});

describe('OpenClaw 2026.x keys in CFG-008/013', () => {
  it('CFG-008 flags agents.defaults.sandbox.mode "off"', async () => {
    expect((await cfg008.run(makeContext([makeConfig({ agents: { defaults: { sandbox: { mode: 'off' } } } })]))).passed).toBe(false);
    expect((await cfg008.run(makeContext([makeConfig({ agents: { defaults: { sandbox: { mode: 'all' } } } })]))).passed).toBe(true);
  });
  it('CFG-013 flags channels.<ch>.dmPolicy "open"', async () => {
    const r = await cfg013.run(makeContext([makeConfig({ channels: { telegram: { dmPolicy: 'open' }, slack: { dmPolicy: 'pairing' } } })]));
    expect(r.passed).toBe(false);
    expect(r.message).toContain('telegram');
    expect(r.message).not.toContain('slack');
    expect((await cfg013.run(makeContext([makeConfig({ channels: { slack: { dmPolicy: 'allowlist' } } })]))).passed).toBe(true);
  });
});

describe('CFG-015 on OpenClaw discovery.mdns.mode', () => {
  it('flags only mode "full"', async () => {
    for (const [mode, passed] of [['off', true], ['minimal', true], ['full', false]] as const) {
      const r = await cfg015.run(makeContext([makeConfig({ discovery: { mdns: { mode } } })]));
      expect(r.passed, mode).toBe(passed);
    }
  });
});

describe('CFG-007: Webhook Missing Auth', () => {
  it('fails when webhook has no auth', async () => {
    const config = makeConfig({ webhooks: [{ url: 'https://example.com/hook' }] });
    const result = await cfg007.run(makeContext([config]));
    console.log(`[CFG-007] webhook no auth → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(false);
  });

  it('passes when webhook has secret', async () => {
    const config = makeConfig({ webhooks: [{ url: 'https://example.com/hook', secret: 'abc123' }] });
    const result = await cfg007.run(makeContext([config]));
    console.log(`[CFG-007] webhook with secret → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(true);
  });

  it('passes when no webhooks configured', async () => {
    const config = makeConfig({});
    const result = await cfg007.run(makeContext([config]));
    console.log(`[CFG-007] no webhooks → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(true);
  });
});

describe('CFG-008: Sandbox Disabled', () => {
  it('fails when sandbox is false', async () => {
    const config = makeConfig({ sandbox: false });
    const result = await cfg008.run(makeContext([config]));
    console.log(`[CFG-008] sandbox=false → passed: ${result.passed}, severity: ${result.severity}, message: ${result.message}`);
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('fails when sandbox is "disabled"', async () => {
    const config = makeConfig({ sandbox: 'disabled' });
    const result = await cfg008.run(makeContext([config]));
    console.log(`[CFG-008] sandbox="disabled" → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(false);
  });

  it('passes when sandbox is true', async () => {
    const config = makeConfig({ sandbox: true });
    const result = await cfg008.run(makeContext([config]));
    console.log(`[CFG-008] sandbox=true → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(true);
  });
});

describe('CFG-009: Default Credentials', () => {
  it('fails with weak password', async () => {
    const config = makeConfig({ auth: { password: 'admin' } });
    const result = await cfg009.run(makeContext([config]));
    console.log(`[CFG-009] password="admin" → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(false);
  });

  it('fails with "changeme"', async () => {
    const config = makeConfig({ auth: { password: 'changeme' } });
    const result = await cfg009.run(makeContext([config]));
    console.log(`[CFG-009] password="changeme" → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(false);
  });

  it('passes with strong credentials', async () => {
    const config = makeConfig({ auth: { password: 'xK9#mP2$vL5nQ8wR' } });
    const result = await cfg009.run(makeContext([config]));
    console.log(`[CFG-009] strong password → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(true);
  });
});

describe('CFG-010: Rate Limiting', () => {
  it('passes on OpenClaw, which rate-limits gateway auth by default', async () => {
    const result = await cfg010.run(makeContext([makeConfig({})]));
    expect(result.passed).toBe(true);
    expect(result.fixable).toBeFalsy();
  });

  it('fails on OpenClaw when gateway.auth.rateLimit is tuned too weak', async () => {
    const weak = makeConfig({ gateway: { auth: { rateLimit: { maxAttempts: 100000, lockoutMs: 0 } } } });
    const result = await cfg010.run(makeContext([weak]));
    expect(result.passed).toBe(false);
    expect(result.message).toContain('maxAttempts 100000');
    const sane = makeConfig({ gateway: { auth: { rateLimit: { maxAttempts: 20, windowMs: 60000, lockoutMs: 300000 } } } });
    expect((await cfg010.run(makeContext([sane]))).passed).toBe(true);
  });

  it('fails when no rate limiting', async () => {
    const config = makeConfig({});
    const result = await cfg010.run(makeContext([config], PLUGIN_AGENT));
    console.log(`[CFG-010] no rate limit → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(false);
  });

  it('passes when rate limiting configured', async () => {
    const config = makeConfig({ rateLimit: { max: 100, window: '1m' } });
    const result = await cfg010.run(makeContext([config], PLUGIN_AGENT));
    console.log(`[CFG-010] rateLimit={max:100,window:1m} → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(true);
  });
});

describe('CFG-012: Auth Bypass', () => {
  it('fails when auth bypass is true', async () => {
    const config = makeConfig({ auth: { bypass: true } });
    const result = await cfg012.run(makeContext([config]));
    console.log(`[CFG-012] auth.bypass=true → passed: ${result.passed}, severity: ${result.severity}, message: ${result.message}`);
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('fails when auth mode is none, without offering a fix (it needs a credential)', async () => {
    const config = makeConfig({ gateway: { auth: { mode: 'none' } } });
    const result = await cfg012.run(makeContext([config]));
    console.log(`[CFG-012] auth.mode="none" → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(false);
    expect(result.fixable).toBe(false);
  });

  it('offers a fix only for an explicit bypass flag', async () => {
    expect((await cfg012.run(makeContext([makeConfig({ auth: { bypass: true } })]))).fixable).toBe(true);
  });

  it('passes with proper auth', async () => {
    const config = makeConfig({ gateway: { auth: { mode: 'bearer' } } });
    const result = await cfg012.run(makeContext([config]));
    console.log(`[CFG-012] auth.mode="bearer" → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(true);
  });
});

describe('CFG-013: DM Policy', () => {
  it('fails when DM policy is open', async () => {
    const config = makeConfig({ dm: { policy: 'open' } });
    const result = await cfg013.run(makeContext([config]));
    console.log(`[CFG-013] dm.policy="open" → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(false);
  });

  it('passes with restricted policy', async () => {
    const config = makeConfig({ dm: { policy: 'restricted' } });
    const result = await cfg013.run(makeContext([config]));
    console.log(`[CFG-013] dm.policy="restricted" → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(true);
  });
});

describe('CFG-014: Tool Policy', () => {
  it('fails when tool policy is permissive', async () => {
    const config = makeConfig({ tools: { policy: 'allow_all' } });
    const result = await cfg014.run(makeContext([config]));
    console.log(`[CFG-014] tools.policy="allow_all" → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(false);
  });

  it('passes with allowlist policy', async () => {
    const config = makeConfig({ tools: { policy: 'allowlist' } });
    const result = await cfg014.run(makeContext([config]));
    console.log(`[CFG-014] tools.policy="allowlist" → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(true);
  });
});

describe('CFG-015: mDNS Broadcast', () => {
  it('fails when mDNS is enabled', async () => {
    const config = makeConfig({ mdns: true });
    const result = await cfg015.run(makeContext([config]));
    console.log(`[CFG-015] mdns=true → passed: ${result.passed}, severity: ${result.severity}, message: ${result.message}`);
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('info');
  });

  it('passes when mDNS is not configured', async () => {
    const config = makeConfig({});
    const result = await cfg015.run(makeContext([config]));
    console.log(`[CFG-015] no mdns → passed: ${result.passed}, message: ${result.message}`);
    expect(result.passed).toBe(true);
  });
});

describe('CFG-011: Node.js CVE-2026-21636', () => {
  it('returns a CheckResult that reflects the running Node version', async () => {
    const result = await cfg011.run(makeContext([makeConfig({})]));
    expect(result.id).toBe('CFG-011');
    expect(result.category).toBe('config');
    expect(result.severity).toBe('warning');
    expect(typeof result.passed).toBe('boolean');
    // Message names the version regardless of pass/fail.
    expect(result.message).toContain(process.version);
  });

  it('does not flag patched current Node versions', async () => {
    // The vulnerable ranges are 18.x ≤ 18.20, 20.x ≤ 20.18, 22.x ≤ 22.12.
    // CI and our dev machines run Node ≥ 20.19, so this should pass.
    const major = parseInt(process.version.slice(1).split('.')[0], 10);
    const minor = parseInt(process.version.slice(1).split('.')[1], 10);
    const knownPatched =
      (major === 20 && minor > 18) ||
      (major === 22 && minor > 12) ||
      major > 22;
    if (!knownPatched) return; // skip silently on older test environments
    const result = await cfg011.run(makeContext([makeConfig({})]));
    expect(result.passed).toBe(true);
  });
});

describe('deep-test 2026-10-15: OpenClaw 2026.9.4 schema', () => {
  const oc = (data: Record<string, unknown>, raw?: string) => makeContext([makeConfig(data, raw)]);

  it('CFG-001 explains "lan" as 0.0.0.0; "auto" (loopback outside containers) is informational here', async () => {
    const lan = await cfg001.run(oc({ gateway: { bind: 'lan' } }));
    expect(lan.evidence?.[0].detail).toContain('0.0.0.0');
    // g4-F1: resolveGatewayBindHost binds "auto" to 0.0.0.0 only in a container
    const auto = await cfg001.run(oc({ gateway: { bind: 'auto' } }));
    expect(auto.passed).toBe(false);
    expect(auto.severity).toBe('info');
    expect(auto.fixable).toBeFalsy();
    // Tailscale serve/funnel forces the gateway onto loopback
    expect((await cfg001.run(oc({ gateway: { bind: 'auto', tailscale: { mode: 'serve' } } }))).passed).toBe(true);
  });

  it('CFG-001: nanobot gateway.host (GET /health only) is info; its websocket channel on 0.0.0.0 is critical (g5-F2)', async () => {
    const health = await cfg001.run(makeContext([makeConfig({ gateway: { host: '0.0.0.0', port: 18790 } })], 'nanobot'));
    expect(health.passed).toBe(false);
    expect(health.severity).toBe('info');
    expect(health.fixable).toBeFalsy();
    const ws = await cfg001.run(makeContext([makeConfig({ gateway: { host: '0.0.0.0' }, channels: { websocket: { host: '0.0.0.0', token: 't' } } })], 'nanobot'));
    expect(ws.severity).toBe('critical');
    expect(ws.evidence?.some(e => e.detail?.includes('channels.websocket.host'))).toBe(true);
  });

  it('CFG-001 agrees with the resolved gateway listener (PicoClaw launcher public, OpenShell bind_address)', async () => {
    const ctx = makeContext([makeConfig({ public: true })], 'picoclaw');
    ctx.installation.gateway = { host: '0.0.0.0', port: 18790 };
    const r = await cfg001.run(ctx);
    expect(r.passed).toBe(false);
    expect(r.evidence?.[0].detail).toContain('0.0.0.0:18790');
    expect(r.fixable).toBeFalsy();
  });

  it('CFG-001 fix rewrites gateway.bind in a JSONC openclaw.json', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vaso-cfg001-'));
    try {
      const file = join(dir, 'openclaw.json');
      const raw = '// comment\n{\n  "gateway": { "bind": "lan", "auth": { "mode": "none" }, },\n  /* x */ "tools": { "exec": { "mode": "full" } },\n}\n';
      await writeFile(file, raw);
      const config: ParsedConfig = { raw, format: 'json', filePath: file, data: { gateway: { bind: 'lan', auth: { mode: 'none' } }, tools: { exec: { mode: 'full' } } } };
      const result = await cfg001.fix!(makeContext([config]));
      expect(result.applied).toBe(true);
      expect(await readFile(file, 'utf8')).toContain('"loopback"');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('CFG-001 fix names the wildcard listeners it leaves alone (Nanobot channels.websocket.host)', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vaso-cfg001-'));
    try {
      const file = join(dir, 'config.json');
      const data = { gateway: { host: '0.0.0.0', port: 18790 }, channels: { websocket: { enabled: true, host: '0.0.0.0', port: 8765 } } };
      await writeFile(file, JSON.stringify(data, null, 2));
      const config: ParsedConfig = { raw: JSON.stringify(data, null, 2), format: 'json', filePath: file, data };
      const result = await cfg001.fix!(makeContext([config], 'nanobot'));
      expect(result.applied).toBe(true);
      expect(result.message).toContain('still on all interfaces: channels.websocket.host');
      const written = JSON.parse(await readFile(file, 'utf8'));
      expect(written.gateway.host).toBe('127.0.0.1');
      expect(written.channels.websocket.host).toBe('0.0.0.0');
      // Only the gateway exposed: nothing is left to name
      const only = { gateway: { host: '0.0.0.0' } };
      await writeFile(file, JSON.stringify(only));
      const r2 = await cfg001.fix!(makeContext([{ raw: JSON.stringify(only), format: 'json', filePath: file, data: only }], 'nanobot'));
      expect(r2.message).not.toContain('still on all interfaces');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('CFG-004 passes a tailnet bind and Tailscale serve, and a comma list of loopback hosts', async () => {
    for (const data of [{ gateway: { bind: 'tailnet' } }, { gateway: { bind: 'lan', tailscale: { mode: 'serve' } } }]) {
      const ctx = oc(data);
      ctx.installation.gateway = {};
      expect((await cfg004.run(ctx)).passed, JSON.stringify(data)).toBe(true);
    }
    const ctx = makeContext([makeConfig({ gateway: { host: '127.0.0.1,::1' } })], 'picoclaw');
    ctx.installation.gateway = { host: '127.0.0.1,::1' };
    expect((await cfg004.run(ctx)).passed).toBe(true);
  });

  it('CFG-004 reads the parsed TLS value, not the raw line (single-line enabled:false + autoGenerate:true)', async () => {
    const data = { gateway: { bind: 'lan', tls: { enabled: false, autoGenerate: true } } };
    const ctx = oc(data, JSON.stringify(data));
    ctx.installation.gateway = { host: '0.0.0.0', tls: false };
    expect((await cfg004.run(ctx)).passed).toBe(false);
    const on = { gateway: { bind: 'lan', tls: { enabled: true } } };
    const ctxOn = oc(on, JSON.stringify(on));
    ctxOn.installation.gateway = { host: '0.0.0.0' };
    expect((await cfg004.run(ctxOn)).passed).toBe(true);
  });

  it('CFG-015 treats discovery.mdns {} as the default "minimal" mode', async () => {
    expect((await cfg015.run(oc({ discovery: { mdns: {} } }))).passed).toBe(true);
    expect((await cfg015.run(oc({ discovery: { mdns: { mode: 'full' } } }))).passed).toBe(false);
  });

  const evade = {
    tools: { exec: { mode: 'ask' }, fs: { workspaceOnly: true } },
    agents: {
      defaults: { sandbox: { mode: 'non-main' } },
      entries: { main: { default: true }, worker: { sandbox: { mode: 'off' }, tools: { exec: { mode: 'full' }, fs: { workspaceOnly: false } } } },
    },
  };

  it('CFG-005/006/008 read agents.entries.<id> overrides', async () => {
    const r5 = await cfg005.run(oc(evade));
    expect(r5.passed).toBe(false);
    expect(r5.evidence?.[0].detail).toContain('agents.entries.worker.tools.exec.mode');
    const r6 = await cfg006.run(oc(evade));
    expect(r6.passed).toBe(false);
    expect(r6.evidence?.[0].detail).toContain('agents.entries.worker');
    const r8 = await cfg008.run(oc(evade));
    expect(r8.passed).toBe(false);
    expect(r8.message).toContain('"worker"');
  });

  it('CFG-005 reads every config, so a sub-agent file set to "full" is not hidden by a strict openclaw.json', async () => {
    const global = { ...makeConfig({ tools: { exec: { mode: 'ask' } } }), filePath: '/h/.openclaw/openclaw.json' };
    const sub = { ...makeConfig({ tools: { exec: { mode: 'full' } } }), filePath: '/h/.openclaw/agents/x/agent.json' };
    const r = await cfg005.run(makeContext([global, sub]));
    expect(r.passed).toBe(false);
    expect(r.evidence?.[0].file).toBe('/h/.openclaw/agents/x/agent.json');
  });

  // OpenClaw 2026.11.2 tool policy: minimal/messaging profiles carry no
  // runtime or fs tools; deny wins; group:runtime / group:fs expand
  it.each([
    [{ tools: { profile: 'messaging' } }, true, true],
    [{ tools: { profile: 'minimal' } }, true, true],
    [{ tools: { deny: ['group:runtime', 'group:fs'] } }, true, true],
    [{ tools: { deny: ['*'] } }, true, true],
    [{ tools: { deny: ['bash'] } }, true, false],
    [{ tools: { allow: ['web_search', 'message'] } }, true, true],
    // alsoAllow widens the profile
    [{ tools: { profile: 'messaging', alsoAllow: ['exec'] } }, false, true],
    [{ tools: { profile: 'coding' } }, false, false],
    [{ tools: { profile: 'full' } }, false, false],
    // an allowlist of plugin tools only is dropped by OpenClaw: core tools stay
    [{ tools: { allow: ['my_plugin_tool'] } }, false, false],
    // an agent's own profile replaces the root one
    [{ tools: { profile: 'messaging' }, agents: { entries: { ops: { tools: { profile: 'coding' } } } } }, false, false],
    [{ tools: { profile: 'coding' }, agents: { entries: { ops: { tools: { profile: 'messaging' } } } } }, false, false],
  ])('CFG-005/006 on %j: exec removed %s, fs removed %s', async (data, noExec, noFs) => {
    expect((await cfg005.run(oc(data))).passed).toBe(noExec);
    expect((await cfg006.run(oc(data))).passed).toBe(noFs);
  });

  it('CFG-005 judges only the agents that keep exec', async () => {
    const data = { tools: { profile: 'messaging', exec: { mode: 'full' } }, agents: { entries: { ops: { tools: { profile: 'coding', exec: { mode: 'ask' } } } } } };
    expect((await cfg005.run(oc(data))).passed).toBe(true);
    const weak = { tools: { profile: 'messaging' }, agents: { entries: { ops: { tools: { profile: 'coding', exec: { mode: 'full' } } } } } };
    const r = await cfg005.run(oc(weak));
    expect(r.passed).toBe(false);
    expect(r.evidence?.map(e => e.detail)).toEqual(['agents.entries.ops.tools.exec.mode: full']);
  });

  it('CFG-005/006 pass a gateway.mode "remote" client (tools run on the remote gateway)', async () => {
    const data = { gateway: { mode: 'remote', remote: { url: 'wss://gw.example.com' } } };
    expect((await cfg005.run(oc(data))).passed).toBe(true);
    expect((await cfg006.run(oc(data))).passed).toBe(true);
  });

  it('CFG-013 flags a per-account dmPolicy "open"', async () => {
    const r = await cfg013.run(oc({ channels: { telegram: { enabled: true, dmPolicy: 'pairing', accounts: { ops: { dmPolicy: 'open' } } } } }));
    expect(r.passed).toBe(false);
    expect(r.evidence?.[0].detail).toBe('channels.telegram.accounts.ops.dmPolicy: open');
  });

  it('CFG-012 flags gateway.controlUi.dangerouslyDisableDeviceAuth', async () => {
    const r = await cfg012.run(oc({ gateway: { auth: { mode: 'token' }, controlUi: { dangerouslyDisableDeviceAuth: true } } }));
    expect(r.passed).toBe(false);
    expect(r.message).toContain('device authentication');
    expect(r.fixable).toBeFalsy();
  });
});

describe('CFG-001 on Hermes', () => {
  it('defers to HM-004 when the API server has a key', async () => {
    const env = { raw: '', format: 'env' as const, filePath: '/h/.hermes/.env', data: { API_SERVER_HOST: '0.0.0.0', API_SERVER_KEY: 'k' } };
    const ctx = makeContext([env]);
    ctx.installation = { ...ctx.installation, agent: 'hermes', gateway: { host: '0.0.0.0', port: 8642 } };
    expect((await cfg001.run(ctx)).passed).toBe(true);
    const open = { ...env, data: { API_SERVER_ENABLED: 'true', API_SERVER_HOST: '0.0.0.0' } };
    const ctx2 = makeContext([open]);
    // Before the start-up key guard (0.9.0) the server runs unauthenticated
    ctx2.installation = { ...ctx2.installation, agent: 'hermes', version: '0.8.0', gateway: { host: '0.0.0.0', port: 8642 } };
    expect((await cfg001.run(ctx2)).passed).toBe(false);
    // 0.15.0+ refuses to start it without a key, and an unknown release is HM-004's call
    for (const version of ['0.21.6', undefined]) {
      ctx2.installation = { ...ctx2.installation, version };
      expect((await cfg001.run(ctx2)).passed, version).toBe(true);
    }
  });
});
