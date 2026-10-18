import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const script = fileURLToPath(new URL('../install.sh', import.meta.url));

/**
 * install.sh against stub `node`, `npm` and `curl`: what it downloads, what
 * it hands npm, and when it falls back to the git ref.
 */
describe.skipIf(process.platform === 'win32')('install.sh', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'vaso-install-'));
    const bin = join(dir, 'bin');
    mkdirSync(bin);
    mkdirSync(join(dir, 'prefix', 'lib'), { recursive: true });
    const stub = (name: string, body: string) => {
      writeFileSync(join(bin, name), `#!/bin/sh\n${body}\n`);
      chmodSync(join(bin, name), 0o755);
    };
    stub('node', 'echo v22.0.0');
    stub('npm', `case "$1" in
  --version) echo "$FAKE_NPM" ;;
  prefix) echo "${dir}/prefix" ;;
  config) echo "$FAKE_ALLOW_GIT" ;;
  install) echo "$@" >> "${dir}/npm-install.log"; [ "$FAKE_NPM_FAIL" = 1 ] && exit 1; exit 0 ;;
esac`);
    // -o <file> … -w '%{http_code}' <url>: write the body, print the status
    stub('curl', `out=""; while [ $# -gt 0 ]; do [ "$1" = "-o" ] && out="$2"; shift; done
[ -n "$out" ] && [ "$FAKE_CODE" = 200 ] && echo tgz > "$out"
printf '%s' "$FAKE_CODE"`);
  });

  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  function install(env: Record<string, string>): { status: number | null; out: string; npm: string } {
    const r = spawnSync('bash', [script], {
      env: { HOME: dir, TMPDIR: dir, PATH: `${join(dir, 'bin')}:/usr/bin:/bin`, VASO_VERSION: 'v9.9.9', FAKE_NPM: '12.0.2', FAKE_ALLOW_GIT: 'none', ...env },
      encoding: 'utf-8',
    });
    const log = join(dir, 'npm-install.log');
    return { status: r.status, out: r.stdout + r.stderr, npm: existsSync(log) ? readFileSync(log, 'utf-8') : '' };
  }

  it('downloads the release tarball and installs it as a local file (npm 12 refuses tarball URLs)', () => {
    const r = install({ FAKE_CODE: '200' });
    expect(r.npm).toMatch(/^install -g \/.*\/vaso-9\.9\.9\.tgz\n$/);
    expect(r.npm).not.toContain('https://');
    expect(r.npm).not.toContain('github:');
  });

  it('a tarball that fails to install is an error, not a git fallback', () => {
    const r = install({ FAKE_CODE: '200', FAKE_NPM_FAIL: '1' });
    expect(r.status).not.toBe(0);
    expect(r.out).toContain('npm could not install the release tarball');
    expect(r.npm).not.toContain('github:');
  });

  it('a download failure (network, proxy) is an error, not a git fallback', () => {
    const r = install({ FAKE_CODE: '000' });
    expect(r.status).not.toBe(0);
    expect(r.out).toContain('Could not download');
    expect(r.npm).toBe('');
  });

  it('no tarball asset falls back to git — on npm 12 with allow-git=none, a clear message instead of an npm error', () => {
    const r = install({ FAKE_CODE: '404' });
    expect(r.status).not.toBe(0);
    expect(r.out).toContain('does not install packages from git by default (allow-git=none)');
    expect(r.out).toContain('--allow-git=all');
    expect(r.npm).toBe('');
  });

  it('no tarball asset on npm 11 installs the git ref', () => {
    const r = install({ FAKE_CODE: '404', FAKE_NPM: '11.4.0', FAKE_ALLOW_GIT: 'undefined' });
    expect(r.npm).toBe('install -g github:vulnex/vaso#v9.9.9\n');
  });
});
