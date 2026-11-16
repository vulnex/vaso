import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, realpath, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { LocalFSProvider } from './local-fs-provider.js';
import { SnapshotFSProvider } from './snapshot-fs-provider.js';
import type { ProbeSnapshot } from './snapshot-types.js';
import { linkScope, skillRootGap, skillTreeAllowed } from './skill-root-scope.js';

/**
 * A home whose name holds a letter with two Unicode normalization forms (é
 * as U+00E9 or e + U+0301; ガ as U+30AC or カ + U+3099), written in the form
 * the disk doesn't store: macOS APFS opens either, so it is the home —
 * refused as the home whether a config, HOME or a link spells it so. The
 * probe respells it as stored and records the respelling (resolvedDirs);
 * local scans resolve it with realpath.
 */
const FORMS = [
  { nfc: 'café', nfd: 'café' },
  { nfc: 'ガ', nfd: 'ガ' },
];

async function normalizationInsensitive(dir: string): Promise<boolean> {
  await writeFile(join(dir, 'café-probe'), '');
  return stat(join(dir, 'café-probe')).then(() => true, () => false);
}

describe.each(FORMS)('a home spelled in another normalization form ($nfc), local scans', ({ nfc, nfd }) => {
  let base: string;
  let home: string;
  let written: string;
  let insensitive = false;

  beforeAll(async () => {
    base = await realpath(await mkdtemp('/tmp/vaso-nrm-'));
    insensitive = await normalizationInsensitive(base);
    home = join(base, nfc, 'hu');
    written = join(base, nfd, 'hu');
    await mkdir(join(home, '.claude', 'skills'), { recursive: true });
    await mkdir(join(home, 'team'), { recursive: true });
    if (insensitive) await symlink(written, join(home, '.claude', 'skills', 'homelink'));
  });
  afterAll(async () => {
    await rm(base, { recursive: true, force: true });
  });

  for (const homeAs of ['stored', 'written'] as const) {
    it(`refuses the home, the folder above it and a skill linked to it (HOME ${homeAs})`, async ctx => {
      if (!insensitive) ctx.skip();
      const h = homeAs === 'stored' ? home : written;
      const fs = Object.assign(Object.create(new LocalFSProvider()) as LocalFSProvider, { homedir: () => h });
      expect(await skillRootGap(fs, written, h)).toBe('home');
      expect(await skillRootGap(fs, home, h)).toBe('home');
      expect(await skillRootGap(fs, join(base, nfd), h)).toBe('outside');
      expect(await skillTreeAllowed(fs, join(written, 'team'), h)).toBe(true);
      const inScope = await linkScope(fs, join(home, '.claude', 'skills'));
      expect(await inScope(join(home, '.claude', 'skills', 'homelink'))).toBe(false);
    });
  }
});

describe.each(FORMS)('a home spelled in another normalization form ($nfc), snapshots', ({ nfc, nfd }) => {
  const home = `/Users/x/${nfc}`;
  const written = `/Users/x/${nfd}`;
  const snapshot = (homedir: string, resolvedDirs?: Record<string, string>) => new SnapshotFSProvider({
    version: 1,
    hostname: 'box',
    platform: 'darwin',
    homedir,
    timestamp: '2026-11-16T00:00:00Z',
    privilege: { uid: 501, username: 'x', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['x'], skippedPaths: [] },
    files: {},
    directories: {},
    commandOutputs: {},
    env: {},
    directoryModes: { [home]: 0o40755 },
    ...(resolvedDirs ? { resolvedDirs } : {}),
  } as ProbeSnapshot);

  it('refuses the other spelling as the home through the respelling the probe recorded', async () => {
    expect(await skillRootGap(snapshot(home, { [written]: home }), written, home)).toBe('home');
    expect(await skillRootGap(snapshot(written, { [written]: home }), home, written)).toBe('home');
  });
});
