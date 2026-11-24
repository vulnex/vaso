#!/usr/bin/env node
// Build the release tarball (vaso-<version>.tgz) without the `prepare` hook.
//
// `prepare` (scripts/prepare.mjs) exists for git installs, where npm prepares
// the dependency and dist/ may need building. A release tarball already ships
// dist/, and npm 11+ reports a blocked install script for every tarball
// install that declares one. So the release is packed from a staging copy of
// exactly the files `npm pack` would ship, with `prepare` (and its script)
// removed — the working tree is never modified.
//
// Usage: node scripts/pack-release.mjs [destination-dir]   (default: cwd)
//
// Also writes vaso-<version>.tgz.sha256 (`<sha256>  vaso-<version>.tgz`, the
// `shasum -a 256` format) next to it: a release asset install.sh checks the
// tarball against before installing it. Prints the tarball path on stdout.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dest = resolve(process.argv[2] ?? process.cwd());
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';

const raw = execFileSync(npm, ['pack', '--dry-run', '--json', '--ignore-scripts'], {
  cwd: root, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'],
});
// npm 10 prints an array, newer npm an object keyed by package name; some
// versions log a build before the JSON
const start = raw.search(/^[[{]/m);
const parsed = JSON.parse(start >= 0 ? raw.slice(start) : raw);
const listing = Array.isArray(parsed) ? parsed[0] : Object.values(parsed)[0];
const stage = mkdtempSync(join(tmpdir(), 'vaso-pack-'));
try {
  for (const { path } of listing.files) {
    if (path === 'package.json' || path === 'scripts/prepare.mjs') continue;
    mkdirSync(dirname(join(stage, path)), { recursive: true });
    cpSync(join(root, path), join(stage, path));
  }
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf-8'));
  delete pkg.scripts.prepare;
  pkg.files = pkg.files.filter(f => f !== 'scripts/prepare.mjs');
  writeFileSync(join(stage, 'package.json'), `${JSON.stringify(pkg, null, 2)}\n`);
  mkdirSync(dest, { recursive: true });
  const out = execFileSync(npm, ['pack', '--ignore-scripts', '--pack-destination', dest], { cwd: stage, encoding: 'utf-8' });
  const tgz = join(dest, out.trim().split('\n').pop());
  writeFileSync(`${tgz}.sha256`, `${createHash('sha256').update(readFileSync(tgz)).digest('hex')}  ${basename(tgz)}\n`);
  console.error(`wrote ${tgz}.sha256`);
  console.log(tgz);
} finally {
  rmSync(stage, { recursive: true, force: true });
}
