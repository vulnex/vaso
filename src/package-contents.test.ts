import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Guards the published npm tarball (the GitHub Release asset users install).
 * npm does not apply .gitignore inside a directory listed in `files`, so
 * listing a whole directory would pack any local, gitignored files in it.
 * Only this allowlist may ever be packed.
 */
const ALLOWED = [
  /^package\.json$/,
  /^README\.md$/,
  /^LICENSE$/,
  /^bin\/vaso$/,
  /^bin\/vaso-quick\.sh$/,
  /^dist\/(cli|index)\.js(\.map)?$/,
  /^dist\/index\.d\.ts$/,
  /^probe\/checksums\.json$/,
];

const root = join(__dirname, '..');

function packedFiles(): string[] {
  const out = execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {
    cwd: root,
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'ignore'],
  });
  const parsed = JSON.parse(out) as unknown;
  // npm 10 prints an array, newer npm an object keyed by package name
  const entry = Array.isArray(parsed) ? parsed[0] : Object.values(parsed as Record<string, unknown>)[0];
  return (entry as { files: { path: string }[] }).files.map(f => f.path);
}

describe('npm package contents', () => {
  it('packs only allowlisted files (no local snapshots, inventories or scan output)', () => {
    const files = packedFiles();
    expect(files.filter(f => !ALLOWED.some(rx => rx.test(f)))).toEqual([]);
    expect(files).toEqual(expect.arrayContaining(['bin/vaso', 'dist/cli.js', 'probe/checksums.json']));
  }, 60_000);

  it('lists no bare directories in package.json files except dist', () => {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf-8')) as { files: string[] };
    const dirs = pkg.files.filter(f => {
      try { return statSync(join(root, f)).isDirectory(); } catch { return false; }
    });
    // A listed directory ships everything in it, gitignored or not
    expect(dirs).toEqual(['dist']);
  });
});
