import { describe, it, expect } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';

const script = fileURLToPath(new URL('../bin/vaso-quick.sh', import.meta.url));

/** Run the quick scan against a throwaway HOME; `files` are relative to
 *  ~/.openclaw unless they start with `~/`. `env` values may use `$HOME`. */
function quick(files: Record<string, string>, mode = 0o600, shell = 'bash', env: Record<string, string> = {}): { status: number | null; out: string } {
  const home = mkdtempSync(join(tmpdir(), 'vaso-quick-'));
  try {
    mkdirSync(join(home, '.openclaw'));
    for (const [name, content] of Object.entries(files)) {
      const file = name.startsWith('~/') ? join(home, name.slice(2)) : join(home, '.openclaw', name);
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, content);
      chmodSync(file, mode);
    }
    const extra = Object.fromEntries(Object.entries(env).map(([k, v]) => [k, v.replace('$HOME', home)]));
    const r = spawnSync(shell, [script], { env: { HOME: home, PATH: '/usr/bin:/bin', ...extra }, encoding: 'utf-8' });
    return { status: r.status, out: r.stdout };
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

/** OpenClaw's file markers on the machine running the tests (a CI job in a
 *  container is one): the quick scan reads them directly. */
const HOST_IS_CONTAINER = ['/.dockerenv', '/run/.containerenv', '/var/run/.containerenv'].some(p => existsSync(p))
  || (() => {
    try {
      return /\/docker\/|cri-containerd-[0-9a-f]|containerd\/[0-9a-f]{64}|\/kubepods[/.]|\blxc\b/.test(readFileSync('/proc/1/cgroup', 'utf-8'));
    } catch {
      return false;
    }
  })();
const FLY = { FLY_MACHINE_ID: 'm', FLY_APP_NAME: 'a' };

describe.skipIf(process.platform === 'win32')('bin/vaso-quick.sh', () => {
  it('parses under bash (a syntax error aborts the quick scan mid-way)', () => {
    expect(() => execFileSync('bash', ['-n', script], { stdio: 'pipe' })).not.toThrow();
  });

  it('reads the OpenClaw 2026.x schema (JSON5, symbolic bind, nested sandbox/auth) and exits 1 on findings', () => {
    const json5 = `{
  // OpenClaw writes JSON5
  gateway: { bind: "lan", auth: {
    mode: "none" } },
  agents: { defaults: { sandbox: {
    mode: "off" } } },
}`;
    const { status, out } = quick({ 'openclaw.json': json5, '.env': 'ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123\n' }, 0o644);
    expect(out).toMatch(/\[x\].*all interfaces/);
    expect(out).toMatch(/\[x\].*API keys/);
    expect(out).toMatch(/\[x\].*permissive permissions/);
    expect(out).toMatch(/\[x\].*Sandbox is disabled/);
    expect(out).toMatch(/\[x\].*Authentication bypass/);
    expect(status).toBe(1);
  });

  it('passes a loopback, sandboxed, token-auth config with owner-only files', () => {
    const { status, out } = quick({ 'openclaw.json': '{ gateway: { bind: "loopback", auth: { mode: "token" } }, agents: { defaults: { sandbox: { mode: "all" } } } }' });
    expect(out).not.toContain('[x]');
    expect(status).toBe(0);
  });

  it('ignores commented-out settings (JSON5 // and /* */) and addresses outside gateway.bind', () => {
    const json5 = `{
  // gateway: { bind: "lan" },   old setting
  /* sandbox: { mode: "off" } */
  gateway: { bind: "loopback", auth: { mode: "token", token: "x" },
    controlUi: { allowedOrigins: ["http://0.0.0.0:18789"] } },
}`;
    expect(quick({ 'openclaw.json': json5 }).out).not.toContain('[x]');
  });

  it('finds sandbox/auth modes after a nested object', () => {
    const json = '{ "gateway": {"bind":"0.0.0.0","auth":{"rateLimit":{"max":5},"mode":"none"}}, "agents": {"defaults": {"sandbox": {"docker": {"image": "x"}, "mode": "off"}}} }';
    const r = quick({ 'openclaw.json': json });
    expect(r.out).toMatch(/\[x\].*all interfaces/);
    expect(r.out).toMatch(/\[x\].*Sandbox is disabled/);
    expect(r.out).toMatch(/\[x\].*Authentication bypass/);
  });

  describe('dt20 g8-F6: matches `vaso scan` on OpenClaw', () => {
    const auto = '{\n  // json5\n  gateway: { bind: "auto", auth: { mode: "token", token: "${OPENCLAW_GATEWAY_TOKEN}" } },\n}';
    const unset = '{ gateway: { mode: "local", auth: { mode: "token", token: "${OPENCLAW_GATEWAY_TOKEN}" } } }';

    it.skipIf(HOST_IS_CONTAINER)('bind "auto" outside a container is loopback: information, not a finding', () => {
      const r = quick({ 'openclaw.json': auto });
      expect(r.out).toContain('[i]');
      expect(r.out).not.toContain('[x]');
      expect(r.status).toBe(0);
      expect(quick({ 'openclaw.json': unset }).out).not.toContain('[x]');
    });

    it('bind "auto" — and an unset bind — inside a container listen on 0.0.0.0 (OpenClaw\'s Fly markers)', () => {
      expect(quick({ 'openclaw.json': auto }, 0o600, 'bash', FLY).out).toMatch(/\[x\].*all interfaces.*auto, in a container/);
      expect(quick({ 'openclaw.json': unset }, 0o600, 'bash', FLY).out).toMatch(/\[x\].*all interfaces.*unset/);
      // both variables are required, as OpenClaw checks
      if (!HOST_IS_CONTAINER) expect(quick({ 'openclaw.json': auto }, 0o600, 'bash', { FLY_MACHINE_ID: 'm' }).out).not.toContain('[x]');
      // Tailscale serve/funnel keeps an unset bind on loopback; remote mode runs no gateway
      const ts = '{ gateway: { mode: "local", tailscale: { mode: "serve" }, auth: { mode: "password" } } }';
      expect(quick({ 'openclaw.json': ts }, 0o600, 'bash', FLY).out).not.toContain('[x]');
      expect(quick({ 'openclaw.json': '{ gateway: { mode: "remote", bind: "lan" } }' }, 0o600, 'bash', FLY).out).not.toContain('[x]');
    });

    it('reads only the config OpenClaw loads and the .env beside it', () => {
      const r = quick({
        'openclaw.json': '{"gateway":{"bind":"loopback"}}',
        'gateway.yaml': 'gateway:\n  bind: 0.0.0.0\nsandbox: false\n',
        'config.json': '{ "sandbox": false, "auth": { "mode": "none" } }',
        'notes.json': '{"k":"sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123"}',
      });
      expect(r.out).not.toContain('[x]');
      expect(r.status).toBe(0);
    });

    it('skips documentation placeholders but reports a real key', () => {
      const placeholders = [
        'OPENAI_API_KEY=sk-your-key-here-1234567890abcdef',
        'ANTHROPIC_API_KEY=sk-ant-replace-me-with-your-real-key',
        'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
        'OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxx',
      ].join('\n');
      expect(quick({ 'openclaw.json': '{}', '.env': placeholders }).out).not.toMatch(/\[x\].*API keys/);
      expect(quick({ 'openclaw.json': '{}', '.env': 'ANTHROPIC_API_KEY=sk-ant-api03-Zq8wLm3vT9kR2pN7aY4cB6dF\n' }).out).toMatch(/\[x\].*API keys/);
    });

    it('honours OPENCLAW_CONFIG_PATH, OPENCLAW_STATE_DIR and OPENCLAW_HOME', () => {
      const lan = '{ gateway: { bind: "lan" } }';
      // the variable names the file read; ~/.openclaw/openclaw.json is not it
      const byPath = quick({ 'openclaw.json': '{ gateway: { bind: "loopback" } }', '~/cfg/my.json': lan }, 0o600, 'bash', { OPENCLAW_CONFIG_PATH: '~/cfg/my.json' });
      expect(byPath.out).toMatch(/\[x\].*all interfaces/);
      const byState = quick({ 'openclaw.json': '{ gateway: { bind: "loopback" } }', '~/state/openclaw.json': lan }, 0o600, 'bash', { OPENCLAW_STATE_DIR: '$HOME/state' });
      expect(byState.out).toContain('/state)');
      expect(byState.out).toMatch(/\[x\].*all interfaces/);
      const byHome = quick({ 'openclaw.json': '{ gateway: { bind: "loopback" } }', '~/alt/.openclaw/openclaw.json': lan }, 0o600, 'bash', { OPENCLAW_HOME: '$HOME/alt' });
      expect(byHome.out).toMatch(/\[x\].*all interfaces/);
    });
  });

  it.skipIf(!existsSync('/bin/bash'))('runs under the system bash (3.2 on macOS)', () => {
    const json = '{ gateway: { bind: "lan" }, agents: { defaults: { sandbox: { docker: { image: "x" }, mode: "off" } } } }';
    const r = quick({ 'openclaw.json': json }, 0o600, '/bin/bash');
    expect(r.out).toMatch(/\[x\].*all interfaces/);
    expect(r.out).toMatch(/\[x\].*Sandbox is disabled/);
    expect(r.status).toBe(1);
  });
});
