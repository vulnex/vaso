#!/usr/bin/env node
/**
 * Generate probe/checksums.json from the locally-built probe binaries.
 *
 * Usage: node scripts/gen-probe-checksums.mjs
 *
 * Reads every probe/dist/vaso-probe-<os>-<arch>, computes its SHA-256, and
 * writes probe/checksums.json keyed by binary name. The `version` field is
 * taken from package.json so the runtime fetcher (src/transport/probe-fetch.ts)
 * can map it to the matching GitHub Release tag (vX.Y.Z).
 *
 * This file SHIPS in the npm package (package.json `files`), so the binary the
 * fetcher downloads is verified against a digest baked into the CLI version —
 * integrity does not depend on trusting the download host. Run this during
 * release prep, on the same binaries you upload as release assets.
 */

import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const distDir = join(repoRoot, 'probe', 'dist');
const outPath = join(repoRoot, 'probe', 'checksums.json');

const { version } = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf-8'));

const binaries = {};
let count = 0;
for (const name of readdirSync(distDir).sort()) {
  if (!name.startsWith('vaso-probe-')) continue;          // skip SHA256SUMS, etc.
  const hash = createHash('sha256').update(readFileSync(join(distDir, name))).digest('hex');
  binaries[name] = `sha256:${hash}`;
  count++;
}

if (count === 0) {
  console.error(`No vaso-probe-* binaries in ${distDir}. Run \`make all\` in probe/ first.`);
  process.exit(1);
}

writeFileSync(outPath, JSON.stringify({ version, binaries }, null, 2) + '\n');
console.log(`Wrote ${outPath} (version ${version}, ${count} binaries)`);
for (const [name, digest] of Object.entries(binaries)) console.log(`  ${name}  ${digest}`);
