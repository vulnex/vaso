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
    stub('node', 'echo "${FAKE_NODE-v22.0.0}"');
    stub('npm', `case "$1" in
  --version) echo "$FAKE_NPM" ;;
  prefix) echo "${dir}/prefix" ;;
  config) echo "$FAKE_ALLOW_GIT" ;;
  install) echo "$@" >> "${dir}/npm-install.log"; [ "$FAKE_NPM_FAIL" = 1 ] && exit 1
    # The installed command reports $FAKE_VASO_VERSION
    if [ -n "$FAKE_VASO_VERSION" ]; then
      mkdir -p "${dir}/prefix/bin"
      printf '#!/bin/sh\necho %s\n' "$FAKE_VASO_VERSION" > "${dir}/prefix/bin/vaso"
      chmod 755 "${dir}/prefix/bin/vaso"
    fi
    exit 0 ;;
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

  // npm 11+ leaves a broken global install from a git ref; npm 12 refuses git by default
  it.each(['12.0.2', '11.4.0', 'x'])('no tarball asset on npm %s: the manual tarball steps, no git install', (npm) => {
    const r = install({ FAKE_CODE: '404', FAKE_NPM: npm, FAKE_ALLOW_GIT: 'undefined' });
    expect(r.status).not.toBe(0);
    expect(r.out).toContain('releases/download/<tag>/vaso-<version>.tgz');
    expect(r.out).toContain('Not installed.');
    expect(r.npm).toBe('');
  });

  it('no tarball asset on npm 10 installs the git ref', () => {
    const r = install({ FAKE_CODE: '404', FAKE_NPM: '10.9.0', FAKE_ALLOW_GIT: 'undefined' });
    expect(r.npm).toBe('install -g github:vulnex/vaso#v9.9.9\n');
  });

  it.each(['', 'garbage', 'vx.1.0'])('a Node.js version that is not a number (%j) is refused', (node) => {
    const r = install({ FAKE_CODE: '200', FAKE_NODE: node });
    expect(r.status).not.toBe(0);
    expect(r.out).toContain('Could not read the Node.js version');
    expect(r.npm).toBe('');
  });

  it('the installed command must report the release version', () => {
    const ok = install({ FAKE_CODE: '200', FAKE_VASO_VERSION: '9.9.9', PATH: `${join(dir, 'prefix', 'bin')}:${join(dir, 'bin')}:/usr/bin:/bin` });
    expect(ok.status).toBe(0);
    expect(ok.out).toContain('VASO v9.9.9 installed successfully');
    rmSync(join(dir, 'npm-install.log'));
    const other = install({ FAKE_CODE: '200', FAKE_VASO_VERSION: '0.1.0' });
    expect(other.status).not.toBe(0);
    expect(other.out).toContain("reports version '0.1.0', expected 9.9.9");
  });

  it('warns when another vaso comes first in PATH', () => {
    const elsewhere = join(dir, 'other');
    mkdirSync(elsewhere);
    writeFileSync(join(elsewhere, 'vaso'), '#!/bin/sh\necho 1.0.0\n');
    chmodSync(join(elsewhere, 'vaso'), 0o755);
    const r = install({ FAKE_CODE: '200', FAKE_VASO_VERSION: '9.9.9', PATH: `${elsewhere}:${join(dir, 'bin')}:/usr/bin:/bin` });
    expect(r.out).toContain(`Another 'vaso' comes first in your PATH: ${join(elsewhere, 'vaso')}`);
  });
});
