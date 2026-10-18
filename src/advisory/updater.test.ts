import { describe, it, expect, vi, afterEach } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { mergeAdvisoryFeed, isAdvisoryFeedStale, fetchAndUpdateAdvisoryFeed } from './updater.js';
import { buildBundledAdvisoryDatabase } from './database.js';
import type { AdvisoryFeedData } from './advisory-types.js';

describe('mergeAdvisoryFeed', () => {
  it('merges feed advisories into bundled database', () => {
    const bundled = buildBundledAdvisoryDatabase();
    const originalCount = bundled.advisories.length;

    const feedData: AdvisoryFeedData = {
      advisories: [
        {
          id: 'CVE-2026-99999',
          title: 'Test advisory from feed',
          agent: 'openclaw',
          affectedVersions: '>=1.0.0 <2.0.0',
          severity: 'warning',
          description: 'Test advisory',
          published: '2026-03-01',
          tags: ['framework'],
        },
      ],
    };

    const merged = mergeAdvisoryFeed(bundled, feedData);
    expect(merged.advisories.length).toBe(originalCount + 1);
    expect(merged.advisories.find(a => a.id === 'CVE-2026-99999')).toBeTruthy();
  });

  it('feed overrides bundled advisory with same ID', () => {
    const bundled = buildBundledAdvisoryDatabase();
    const existingId = bundled.advisories[0].id;

    const feedData: AdvisoryFeedData = {
      advisories: [
        {
          id: existingId,
          title: 'Updated advisory',
          agent: 'openclaw',
          affectedVersions: '>=1.0.0 <3.0.0',
          severity: 'critical',
          description: 'Updated description',
          published: '2026-03-01',
          tags: ['framework'],
        },
      ],
    };

    const merged = mergeAdvisoryFeed(bundled, feedData);
    const updated = merged.advisories.find(a => a.id === existingId);
    expect(updated?.title).toBe('Updated advisory');
    expect(updated?.affectedVersions).toBe('>=1.0.0 <3.0.0');
  });

  it('deduplicates by advisory ID', () => {
    const bundled = buildBundledAdvisoryDatabase();
    const originalCount = bundled.advisories.length;

    const feedData: AdvisoryFeedData = {
      advisories: bundled.advisories.map(a => ({ ...a })),
    };

    const merged = mergeAdvisoryFeed(bundled, feedData);
    expect(merged.advisories.length).toBe(originalCount);
  });
});

describe('isAdvisoryFeedStale', () => {
  it('returns false when metadata dir does not exist (user not opted in)', () => {
    expect(isAdvisoryFeedStale(7, '/nonexistent/path')).toBe(false);
  });
});

describe('fetchAndUpdateAdvisoryFeed', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('checks the signature before the version: an unsigned "older" feed is a failure, not "not newer"', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vaso-adv-'));
    const { publicKey } = generateKeyPairSync('ed25519', { publicKeyEncoding: { type: 'spki', format: 'pem' } });
    await writeFile(join(dir, 'metadata.json'), JSON.stringify({ lastUpdated: '2026-01-01', feedVersion: 9, feedUrl: 'x', lastCheckAt: new Date(0).toISOString() }));
    const feed = Buffer.from(JSON.stringify({ meta: { version: 1, timestamp: 't', description: 'd' }, data: { advisories: [] } }));
    const sig = Buffer.from(Buffer.alloc(64).toString('base64'));
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
      const body = url.endsWith('.sig') ? sig : feed;
      return Promise.resolve({ ok: true, arrayBuffer: () => Promise.resolve(body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength)) });
    }));
    const r = await fetchAndUpdateAdvisoryFeed({ feedUrl: 'https://example.com/a.json', feedDir: dir, publicKeyPem: publicKey as unknown as string });
    expect(r.success).toBe(false);
    expect(r.message).toContain('signature verification failed');
    await rm(dir, { recursive: true, force: true });
  });
});
