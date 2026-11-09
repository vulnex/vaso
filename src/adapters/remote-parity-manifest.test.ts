import { describe, it, expect } from 'vitest';
import { SnapshotFSProvider } from '../core/snapshot-fs-provider.js';
import type { ProbeSnapshot, FileEntry } from '../core/snapshot-types.js';
import { buildProbeManifest } from '../core/manifest-builder.js';
import { captureConfigLoadErrors } from '../core/config-loader.js';
import { devinAdapter } from './devin.js';
import { qwenCodeAdapter } from './qwen-code.js';
import { grokBotAdapter } from './grok-bot.js';
import { picoclawAdapter } from './picoclaw.js';
import { nanoclawAdapter, findNanoclawCheckouts } from './nanoclaw.js';
import { npmPackageJsonGlobs } from './nvm-binary.js';
import { readPackageVersion } from './version-query.js';

// Remote (probe snapshot) scans must see what local scans see (dt19 fix round).

const HOME = '/home/u';

function snapshot(files: Record<string, Partial<FileEntry>>, extra: Partial<ProbeSnapshot> = {}): SnapshotFSProvider {
  const entries: Record<string, FileEntry> = {};
  for (const [p, e] of Object.entries(files)) entries[p] = { content: '', mode: 0o644, exists: true, ...e };
  return new SnapshotFSProvider({
    version: 1, hostname: 'h', platform: 'linux', homedir: HOME, timestamp: '2026-11-08T00:00:00Z',
    privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
    files: entries, directories: {}, commandOutputs: {}, env: {},
    ...extra,
  });
}

describe('probe manifest coverage', () => {
  it('Devin: collects every always-on rules file DEV-007 reads', () => {
    const m = devinAdapter.getProbeManifest!();
    for (const p of ['~/.config/devin/AGENTS.local.md', '~/.config/devin/AGENT.md', '~/.config/devin/.windsurfrules', '~/.devin/global_rules.md']) {
      expect(m.filePaths).toContain(p);
    }
    expect(m.globPatterns).toContain('~/.devin/rules/*.md');
  });

  it('Qwen: collects a context file renamed with context.fileName (markdown)', () => {
    expect(qwenCodeAdapter.getProbeManifest!().globPatterns).toContain('~/.qwen/*.md');
  });

  it('pnpm: names the global store package.json without a wildcard (the package dir is a symlink)', () => {
    const globs = npmPackageJsonGlobs('@google/gemini-cli');
    expect(globs).toContain('~/Library/pnpm/global/5/node_modules/@google/gemini-cli/package.json');
    expect(globs).toContain('~/.local/share/pnpm/global/5/node_modules/@google/gemini-cli/package.json');
  });

  it('pnpm: versions a global shim from the store on a snapshot', async () => {
    const fs = snapshot({
      [`${HOME}/Library/pnpm/gemini`]: {},
      [`${HOME}/Library/pnpm/global/5/node_modules/@google/gemini-cli/package.json`]: { content: '{"name":"@google/gemini-cli","version":"0.2.0"}' },
    });
    expect(await readPackageVersion(`${HOME}/Library/pnpm/gemini`, fs, '@google/gemini-cli')).toBe('0.2.0');
    expect(await readPackageVersion(`${HOME}/Library/pnpm/gemini`, fs, '@openai/codex')).toBeUndefined();
  });

  it('Grok Bot: stats the GROK_BOT_SIDECAR_APP target (metadata only) and keeps endpoint URLs to their origin', () => {
    const m = grokBotAdapter.getProbeManifest!();
    expect(m.metadataGlobPatterns).toContain('${GROK_BOT_SIDECAR_APP}');
    expect([...m.filePaths, ...m.globPatterns]).not.toContain('${GROK_BOT_SIDECAR_APP}');
    expect(m.envOriginOnly).toEqual(expect.arrayContaining(['SAND_BACKEND_URL', 'SAND_HOST_GATEWAY_URL', 'SAND_HTTPS_PROXY']));
    const merged = buildProbeManifest([grokBotAdapter]);
    expect(merged.envOriginOnly).toEqual(expect.arrayContaining(['SAND_BACKEND_URL', 'CURSOR_WEBSITE_URL']));
    // every origin-only variable is one the probe collects
    for (const name of merged.envOriginOnly!) expect(merged.envPrefixes.some(p => name.startsWith(p))).toBe(true);
  });

  it('PicoClaw: collects launcher-config.json and .security.yml next to a relocated $PICOCLAW_CONFIG', () => {
    const m = picoclawAdapter.getProbeManifest!();
    expect(m.filePaths).toEqual(expect.arrayContaining(['${PICOCLAW_CONFIG}/../launcher-config.json', '${PICOCLAW_CONFIG}/../.security.yml']));
  });

  it('NanoClaw: clone parents are matched against the listing, never stat\'ed by a case-folding literal', () => {
    // every-case classes: ~/Projects, ~/projects, ~/GitHub, ~/SRC all match
    const globs = nanoclawAdapter.getProbeManifest!().globPatterns.filter(g => g.includes('[rR][oO][jJ]'));
    expect(globs.length).toBeGreaterThan(0);
    for (const g of globs) {
      expect(g).toContain('[pP][rR][oO][jJ][eE][cC][tT][sS]');
      expect(g).toContain('[gG][iI][tT][hH][uU][bB]');
      expect(g).not.toMatch(/[{,](projects|github|src)[,}]/i);
    }
  });
});

describe('NanoClaw checkout discovery', () => {
  it('keeps the on-disk case of the clone parent (case-insensitive file systems)', async () => {
    const pkg = { content: '{"name":"nanoclaw","version":"2.4.0"}' };
    // ~/projects opens ~/Projects on macOS: both spellings read the same checkout
    const fs = snapshot({ [`${HOME}/Projects/NanoClaw-bot/package.json`]: pkg }, { platform: 'darwin' });
    const caseFolding = Object.assign(Object.create(Object.getPrototypeOf(fs)), fs, {
      readdir: async (p: string) => (p.toLowerCase() === `${HOME}/projects` ? ['NanoClaw-bot'] : fs.readdir(p)),
      readFile: async (p: string) => fs.readFile(p.replace(`${HOME}/projects/`, `${HOME}/Projects/`)),
    });
    const found = await findNanoclawCheckouts(HOME, caseFolding);
    expect(found.map(c => c.dir)).toEqual([`${HOME}/Projects/NanoClaw-bot`]);
  });

  it('reports a checkout the ncl link names but the probe did not collect, with a CONFIG-LOAD note', async () => {
    const fs = snapshot({ [`${HOME}/.local/bin/ncl`]: { omitted: 'metadata', contentOmitted: true } }, {
      symlinks: { [`${HOME}/.local/bin/ncl`]: '/srv/apps/nanoclaw-v2/bin/ncl' },
    });
    const { result, loadErrors } = await captureConfigLoadErrors(() => findNanoclawCheckouts(HOME, fs));
    expect(result.map(c => c.dir)).toEqual(['/srv/apps/nanoclaw-v2']);
    expect(loadErrors).toEqual([expect.objectContaining({ filePath: '/srv/apps/nanoclaw-v2', message: expect.stringContaining('~/.local/bin/ncl') })]);
  });

  it('does not take another tool\'s ncl, or a dangling link, for an uncollected checkout', async () => {
    for (const target of ['/opt/conda/envs/ncl_stable/bin/ncl', '/srv/apps/helper/bin/ncl']) {
      const fs = snapshot({ [`${HOME}/.local/bin/ncl`]: { omitted: 'metadata', contentOmitted: true } }, {
        symlinks: { [`${HOME}/.local/bin/ncl`]: target },
      });
      const { result, loadErrors } = await captureConfigLoadErrors(() => findNanoclawCheckouts(HOME, fs));
      expect(result).toEqual([]);
      expect(loadErrors).toEqual([]);
    }
  });

  it('says so when a service unit names a checkout outside the collected paths', async () => {
    const unit = `${HOME}/.config/systemd/user/nanoclaw-v2-deadbeef.service`;
    const fs = snapshot({ [unit]: { content: '[Service]\nWorkingDirectory=/srv/bot2\nExecStart=/usr/bin/node /srv/bot2/dist/index.js\n' } });
    const { result, loadErrors } = await captureConfigLoadErrors(() => findNanoclawCheckouts(HOME, fs));
    expect(result.map(c => c.dir)).toEqual(['/srv/bot2']);
    expect(loadErrors[0]).toMatchObject({ filePath: '/srv/bot2', message: expect.stringContaining('service definition') });
  });
});
