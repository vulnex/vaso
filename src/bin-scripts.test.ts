import { describe, it, expect } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const script = fileURLToPath(new URL('../bin/vaso-quick.sh', import.meta.url));

function quick(files: Record<string, string>, mode = 0o600, shell = 'bash'): { status: number | null; out: string } {
  const home = mkdtempSync(join(tmpdir(), 'vaso-quick-'));
  try {
    mkdirSync(join(home, '.openclaw'));
    for (const [name, content] of Object.entries(files)) {
      writeFileSync(join(home, '.openclaw', name), content);
      chmodSync(join(home, '.openclaw', name), mode);
    }
    const r = spawnSync(shell, [script], { env: { HOME: home, PATH: '/usr/bin:/bin' }, encoding: 'utf-8' });
    return { status: r.status, out: r.stdout };
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

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

  it('ignores commented-out settings (JSON5 // and /* */, YAML #) and addresses outside gateway.bind', () => {
    const json5 = `{
  // gateway: { bind: "lan" },   old setting
  /* sandbox: { mode: "off" } */
  gateway: { bind: "loopback", auth: { mode: "token", token: "x" },
    controlUi: { allowedOrigins: ["http://0.0.0.0:18789"] } },
}`;
    expect(quick({ 'openclaw.json': json5 }).out).not.toContain('[x]');
    const yaml = 'gateway:\n  # bind: lan\n  bind: loopback   # was lan\n  auth:\n    mode: token\n';
    expect(quick({ 'openclaw.yaml': yaml }).out).not.toContain('[x]');
  });

  it('finds sandbox/auth modes after a nested object, in JSON and YAML', () => {
    const json = '{ "gateway": {"bind":"0.0.0.0","auth":{"rateLimit":{"max":5},"mode":"none"}}, "agents": {"defaults": {"sandbox": {"docker": {"image": "x"}, "mode": "off"}}} }';
    const r = quick({ 'openclaw.json': json });
    expect(r.out).toMatch(/\[x\].*all interfaces/);
    expect(r.out).toMatch(/\[x\].*Sandbox is disabled/);
    expect(r.out).toMatch(/\[x\].*Authentication bypass/);
    const yaml = 'gateway:\n  bind: "lan"\n  auth:\n    rateLimit:\n      max: 5\n    mode: none\nagents:\n  defaults:\n    sandbox:\n      docker:\n        image: x\n      mode: off\n';
    const y = quick({ 'openclaw.yaml': yaml });
    expect(y.out).toMatch(/\[x\].*all interfaces/);
    expect(y.out).toMatch(/\[x\].*Sandbox is disabled/);
    expect(y.out).toMatch(/\[x\].*Authentication bypass/);
  });

  it.skipIf(!existsSync('/bin/bash'))('runs under the system bash (3.2 on macOS)', () => {
    const json = '{ gateway: { bind: "lan" }, agents: { defaults: { sandbox: { docker: { image: "x" }, mode: "off" } } } }';
    const r = quick({ 'openclaw.json': json }, 0o600, '/bin/bash');
    expect(r.out).toMatch(/\[x\].*all interfaces/);
    expect(r.out).toMatch(/\[x\].*Sandbox is disabled/);
    expect(r.status).toBe(1);
  });
});
