/**
 * Lazy resolution of the vaso-probe binary for remote (SSH) scanning.
 *
 * The probe is a Go binary built out-of-band (probe/Makefile) and is NOT shipped
 * in the npm package. To keep the install Node-only while still making remote
 * scanning work out of the box, we resolve the matching binary on first use:
 *
 *   (a) a locally-built tree (probe/dist/) wins — the dev / hand-built path,
 *       fully offline, no verification (the user built it themselves);
 *   (b) a version-scoped cache (~/.vaso/probe/<version>/) — offline after the
 *       first fetch;
 *   (c) otherwise download the single matching asset from this version's GitHub
 *       Release and verify it against probe/checksums.json, which ships inside
 *       the npm package — so integrity is anchored to the installed CLI version,
 *       not to trusting the download host.
 *
 * A checksum mismatch is fatal: VASO never runs an unverified probe.
 */

import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir, access, chmod } from 'node:fs/promises';
import { constants as FS } from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';

export interface ResolveProbeOptions {
  /** `<vasoRoot>/probe/dist` — locally-built binaries take precedence. */
  probeBinDir: string;
  /** Override the package root (defaults to `<probeBinDir>/../..`). Test seam. */
  pkgRoot?: string;
  /** Override the download cache root (defaults to `~/.vaso/probe`). Test seam. */
  cacheRoot?: string;
  /** GitHub `owner/repo` to fetch release assets from. */
  repo?: string;
  /** Injectable fetch (test seam). */
  fetchImpl?: typeof fetch;
}

interface ProbeChecksums {
  version: string;
  /** binary name → "sha256:<hex>" */
  binaries: Record<string, string>;
}

async function isFile(p: string): Promise<boolean> {
  try {
    await access(p, FS.F_OK);
    return true;
  } catch {
    return false;
  }
}

function sha256(buf: Buffer): string {
  return 'sha256:' + createHash('sha256').update(buf).digest('hex');
}

async function loadChecksums(pkgRoot: string): Promise<ProbeChecksums> {
  const path = join(pkgRoot, 'probe', 'checksums.json');
  let raw: string;
  try {
    raw = await readFile(path, 'utf-8');
  } catch {
    throw new Error(
      'probe/checksums.json is missing from this VASO install, so a fetched probe ' +
        'binary cannot be verified.\n' +
        '  Reinstall VASO, or build the probe locally: cd probe && make',
    );
  }
  return JSON.parse(raw) as ProbeChecksums;
}

/**
 * Resolve a local path to a verified vaso-probe binary for the given platform,
 * downloading and caching it on first use. Throws with actionable guidance if
 * the binary cannot be resolved or fails verification.
 */
export async function resolveProbeBinary(
  os: string,
  arch: string,
  opts: ResolveProbeOptions,
): Promise<string> {
  const name = `vaso-probe-${os}-${arch}`;
  const pkgRoot = opts.pkgRoot ?? join(opts.probeBinDir, '..', '..');
  const cacheRoot = opts.cacheRoot ?? join(homedir(), '.vaso', 'probe');
  const repo = opts.repo ?? 'vulnex/vaso';
  const fetchImpl = opts.fetchImpl ?? fetch;

  // (a) Locally-built tree wins — offline, user-built, no verification needed.
  const local = join(opts.probeBinDir, name);
  if (await isFile(local)) return local;

  const sums = await loadChecksums(pkgRoot);
  const expected = sums.binaries[name];
  if (!expected) {
    throw new Error(
      `This VASO build (${sums.version}) ships no probe checksum for ${os}/${arch}, ` +
        `so remote scanning of that platform is unsupported.\n` +
        `  Build a probe locally if needed: cd probe && make`,
    );
  }

  // (b) Version-scoped cache — re-verify in case the cached file was tampered with.
  const cached = join(cacheRoot, sums.version, name);
  if (await isFile(cached)) {
    const buf = await readFile(cached);
    if (sha256(buf) === expected) return cached;
    // Corrupt/stale cache entry — fall through and re-download.
  }

  // (c) Download the single matching asset from this version's release.
  const url = `https://github.com/${repo}/releases/download/v${sums.version}/${name}`;
  let res: Response;
  try {
    res = await fetchImpl(url);
  } catch (err) {
    throw new Error(
      `Failed to download vaso-probe for ${os}/${arch} from ${url}: ${(err as Error).message}\n` +
        `  Build it locally instead: cd probe && make`,
    );
  }
  if (!res.ok) {
    throw new Error(
      `vaso-probe asset for ${os}/${arch} not found (HTTP ${res.status} at ${url}).\n` +
        `  This VASO release may not publish probe binaries; build one locally: cd probe && make`,
    );
  }

  const buf = Buffer.from(await res.arrayBuffer());
  const got = sha256(buf);
  if (got !== expected) {
    throw new Error(
      `Checksum mismatch for downloaded ${name}: expected ${expected}, got ${got}. ` +
        `Refusing to use it.`,
    );
  }

  await mkdir(dirname(cached), { recursive: true });
  await writeFile(cached, buf);
  await chmod(cached, 0o755);
  return cached;
}
