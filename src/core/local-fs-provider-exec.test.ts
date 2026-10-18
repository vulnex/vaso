import { describe, it, expect } from 'vitest';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { LocalFSProvider } from './local-fs-provider.js';

describe.skipIf(process.platform === 'win32')('LocalFSProvider isolateHome', () => {
  const fs = new LocalFSProvider();
  const script = 'echo "$HOME"; mkdir -p "$HOME/.agent-state"';

  it('runs with a throwaway HOME and cwd that are removed afterwards', async () => {
    const home = fs.execSync('sh', ['-c', script], { isolateHome: true }).trim();
    expect(home).not.toBe(homedir());
    expect(home).toContain('vaso-exec-');
    expect(existsSync(home)).toBe(false);

    const res = await fs.exec('sh', ['-c', 'echo "$HOME"; pwd'], { isolateHome: true });
    const [h, cwd] = res.stdout.trim().split('\n');
    expect(h).not.toBe(homedir());
    expect(cwd.endsWith(h.split('/').pop()!)).toBe(true);
    expect(existsSync(h)).toBe(false);
  });

  it('leaves HOME alone without the option', () => {
    expect(fs.execSync('sh', ['-c', 'echo "$HOME"']).trim()).toBe(process.env.HOME);
  });
});

// A version shim that leaves a background process holding stdout kept the scan
// waiting for that process (30 s), past any timeout.
describe.skipIf(process.platform === 'win32')('LocalFSProvider exec timeouts', () => {
  const fs = new LocalFSProvider();
  // Polls briefly: a killed orphan is gone once init has reaped it
  const alive = async (pid: number) => {
    for (let i = 0; i < 20; i++) {
      try {
        process.kill(pid, 0);
      } catch {
        return false;
      }
      await new Promise(r => setTimeout(r, 50));
    }
    return true;
  };
  const shim = 'sleep 30 & echo $! ; echo "tool 1.2.3"';

  it('returns once the command exits, and kills what it left running', async () => {
    let t = Date.now();
    const out = fs.execSync('sh', ['-c', shim], { timeout: 5000 });
    expect(Date.now() - t).toBeLessThan(3000);
    expect(out).toContain('tool 1.2.3');
    // (execFileSync doesn't say which group it was; the leftover no longer
    // holds anything the scan waits for)
    process.kill(Number(out.split('\n')[0]), 'SIGKILL');

    t = Date.now();
    const res = await fs.exec('sh', ['-c', shim], { timeout: 5000 });
    expect(Date.now() - t).toBeLessThan(3000);
    expect(res).toMatchObject({ exitCode: 0 });
    expect(res.stdout).toContain('tool 1.2.3');
    expect(await alive(Number(res.stdout.split('\n')[0]))).toBe(false);
  });

  it('enforces the timeout on a command that never exits', async () => {
    let t = Date.now();
    expect(() => fs.execSync('sh', ['-c', 'echo partial; sleep 30'], { timeout: 300 })).toThrow(/timed out/);
    expect(Date.now() - t).toBeLessThan(3000);
    t = Date.now();
    const res = await fs.exec('sh', ['-c', 'sleep 30'], { timeout: 300 });
    expect(Date.now() - t).toBeLessThan(3000);
    expect(res.exitCode).not.toBe(0);
  });

  it('keeps exit status, stderr and missing-command semantics', async () => {
    expect(await fs.exec('sh', ['-c', 'echo err >&2; exit 3'])).toEqual({ stdout: '', stderr: 'err\n', exitCode: 3 });
    expect((await fs.exec('/nonexistent/vaso-cmd', [])).exitCode).toBe(127);
    try {
      fs.execSync('sh', ['-c', 'echo out; exit 2']);
      expect.unreachable();
    } catch (err) {
      expect(err).toMatchObject({ status: 2, stdout: 'out\n' });
    }
    expect(() => fs.execSync('/nonexistent/vaso-cmd', [])).toThrow(/ENOENT/);
  });
});
