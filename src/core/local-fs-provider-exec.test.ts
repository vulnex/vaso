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
