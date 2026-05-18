import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import { generateKeyPairSync, sign, createPrivateKey } from 'node:crypto';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  verifyFeedSignature,
  deserializePatterns,
  deserializeBinaryPatterns,
  mergeFeedIntoDatabase,
  isFeedStale,
  loadCachedFeed,
  fetchAndUpdateFeed,
} from './updater.js';
import {
  buildBundledDatabase,
  getIOCDatabase,
  initIOCDatabase,
  reloadIOCDatabase,
} from './database.js';
import type { IOCFeed, IOCFeedData, IOCFeedMetadata } from './feed-types.js';
import type { IOCDatabase } from './database.js';

// ── Test keypair ────────────────────────────────────────────────────

let testPublicKeyPem: string;
let testPrivateKeyPem: string;

function signFeed(feedBytes: Buffer): string {
  const privateKey = createPrivateKey(testPrivateKeyPem);
  const sig = sign(null, feedBytes, privateKey);
  return sig.toString('base64');
}

function makeFeed(overrides: Partial<IOCFeed> = {}): IOCFeed {
  return {
    meta: { version: 1, timestamp: new Date().toISOString(), description: 'test feed' },
    data: {},
    ...overrides,
  };
}

beforeAll(() => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  testPublicKeyPem = publicKey;
  testPrivateKeyPem = privateKey;
});

// ── verifyFeedSignature ─────────────────────────────────────────────

describe('verifyFeedSignature', () => {
  it('returns true for a valid signature', () => {
    const data = Buffer.from('{"meta":{"version":1},"data":{}}');
    const sig = signFeed(data);
    expect(verifyFeedSignature(data, sig, testPublicKeyPem)).toBe(true);
  });

  it('returns false for tampered data', () => {
    const data = Buffer.from('{"meta":{"version":1},"data":{}}');
    const sig = signFeed(data);
    const tampered = Buffer.from('{"meta":{"version":2},"data":{}}');
    expect(verifyFeedSignature(tampered, sig, testPublicKeyPem)).toBe(false);
  });

  it('returns false for wrong key', () => {
    const data = Buffer.from('test data');
    const sig = signFeed(data);
    const { publicKey: otherKey } = generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    expect(verifyFeedSignature(data, sig, otherKey)).toBe(false);
  });

  it('returns false for malformed base64', () => {
    const data = Buffer.from('test data');
    expect(verifyFeedSignature(data, '!!!not-base64!!!', testPublicKeyPem)).toBe(false);
  });

  it('returns false for wrong signature length', () => {
    const data = Buffer.from('test data');
    // 32 bytes instead of 64
    const shortSig = Buffer.alloc(32).toString('base64');
    expect(verifyFeedSignature(data, shortSig, testPublicKeyPem)).toBe(false);
  });
});

// ── deserializePatterns ─────────────────────────────────────────────

describe('deserializePatterns', () => {
  it('converts source strings to RegExp', () => {
    const result = deserializePatterns([
      { source: 'foo.*bar' },
      { source: 'baz', flags: 'i' },
    ]);
    expect(result).toHaveLength(2);
    expect(result[0]).toBeInstanceOf(RegExp);
    expect(result[0].source).toBe('foo.*bar');
    expect(result[0].flags).toBe('');
    expect(result[1].flags).toBe('i');
  });

  it('applies flags correctly', () => {
    const result = deserializePatterns([{ source: 'test', flags: 'gi' }]);
    expect(result[0].flags).toBe('gi');
  });

  it('handles empty array', () => {
    expect(deserializePatterns([])).toEqual([]);
  });
});

// ── deserializeBinaryPatterns ───────────────────────────────────────

describe('deserializeBinaryPatterns', () => {
  it('converts hex string to Buffer pattern', () => {
    const result = deserializeBinaryPatterns([
      { name: 'test', pattern: '7f454c46', type: 'buffer' },
    ]);
    expect(result).toHaveLength(1);
    expect(result[0].type).toBe('buffer');
    expect(Buffer.isBuffer(result[0].pattern)).toBe(true);
    expect((result[0].pattern as Buffer).toString('hex')).toBe('7f454c46');
  });

  it('converts regex source to RegExp pattern', () => {
    const result = deserializeBinaryPatterns([
      { name: 'test', pattern: 'eval\\(', type: 'regex', flags: 'i' },
    ]);
    expect(result).toHaveLength(1);
    expect(result[0].type).toBe('regex');
    expect(result[0].pattern).toBeInstanceOf(RegExp);
    expect((result[0].pattern as RegExp).flags).toBe('i');
  });

  it('handles empty array', () => {
    expect(deserializeBinaryPatterns([])).toEqual([]);
  });
});

// ── mergeFeedIntoDatabase ───────────────────────────────────────────

describe('mergeFeedIntoDatabase', () => {
  let bundled: IOCDatabase;

  beforeEach(() => {
    bundled = buildBundledDatabase();
  });

  it('adds new IPs from feed', () => {
    const feedData: IOCFeedData = { c2Ips: ['10.0.0.1', '10.0.0.2'] };
    const merged = mergeFeedIntoDatabase(bundled, feedData);
    expect(merged.c2Ips).toContain('10.0.0.1');
    expect(merged.c2Ips).toContain('10.0.0.2');
    // Bundled IPs still present
    expect(merged.c2Ips).toContain('185.199.228.220');
  });

  it('deduplicates strings', () => {
    const feedData: IOCFeedData = { c2Ips: ['185.199.228.220', '10.0.0.1'] };
    const merged = mergeFeedIntoDatabase(bundled, feedData);
    const count = merged.c2Ips.filter((ip) => ip === '185.199.228.220').length;
    expect(count).toBe(1);
  });

  it('leaves bundled unchanged with empty feed', () => {
    const merged = mergeFeedIntoDatabase(bundled, {});
    expect(merged.c2Ips).toEqual(bundled.c2Ips);
    expect(merged.maliciousDomains).toEqual(bundled.maliciousDomains);
    expect(merged.fileHashes).toEqual(bundled.fileHashes);
  });

  it('merges all 8 fields', () => {
    const feedData: IOCFeedData = {
      c2Ips: ['10.0.0.1'],
      maliciousDomains: ['evil.test'],
      fileHashes: ['abc123'],
      maliciousPublishers: ['badguy'],
      maliciousSkillPatterns: [{ source: 'newpattern', flags: 'i' }],
      trustedSkillNames: ['new-skill'],
      trustedMCPPackages: ['@new/package'],
      binaryPatterns: [{ name: 'test', pattern: 'deadbeef', type: 'buffer' }],
    };
    const merged = mergeFeedIntoDatabase(bundled, feedData);
    expect(merged.c2Ips.length).toBe(bundled.c2Ips.length + 1);
    expect(merged.maliciousDomains.length).toBe(bundled.maliciousDomains.length + 1);
    expect(merged.fileHashes.length).toBe(bundled.fileHashes.length + 1);
    expect(merged.maliciousPublishers.length).toBe(bundled.maliciousPublishers.length + 1);
    expect(merged.maliciousSkillPatterns.length).toBe(bundled.maliciousSkillPatterns.length + 1);
    expect(merged.trustedSkillNames.length).toBe(bundled.trustedSkillNames.length + 1);
    expect(merged.trustedMCPPackages.length).toBe(bundled.trustedMCPPackages.length + 1);
    expect(merged.binaryPatterns.length).toBe(bundled.binaryPatterns.length + 1);
  });

  it('always includes bundled data', () => {
    const feedData: IOCFeedData = { c2Ips: ['10.0.0.1'] };
    const merged = mergeFeedIntoDatabase(bundled, feedData);
    for (const ip of bundled.c2Ips) {
      expect(merged.c2Ips).toContain(ip);
    }
  });
});

// ── isFeedStale ─────────────────────────────────────────────────────

describe('isFeedStale', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), 'vaso-stale-'));
  });

  afterEach(async () => {
    await rm(tmpDir, { recursive: true, force: true });
  });

  it('returns false when no metadata exists (user not opted in)', () => {
    expect(isFeedStale(7, tmpDir)).toBe(false);
  });

  it('returns false for recent metadata', async () => {
    const meta: IOCFeedMetadata = {
      lastUpdated: new Date().toISOString(),
      feedVersion: 1,
      feedUrl: 'https://example.com/feed.json',
      lastCheckAt: new Date().toISOString(),
    };
    await writeFile(join(tmpDir, 'metadata.json'), JSON.stringify(meta));
    expect(isFeedStale(7, tmpDir)).toBe(false);
  });

  it('returns true for old metadata', async () => {
    const old = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000); // 30 days ago
    const meta: IOCFeedMetadata = {
      lastUpdated: old.toISOString(),
      feedVersion: 1,
      feedUrl: 'https://example.com/feed.json',
      lastCheckAt: old.toISOString(),
    };
    await writeFile(join(tmpDir, 'metadata.json'), JSON.stringify(meta));
    expect(isFeedStale(7, tmpDir)).toBe(true);
  });

  it('supports custom threshold', async () => {
    const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000);
    const meta: IOCFeedMetadata = {
      lastUpdated: twoHoursAgo.toISOString(),
      feedVersion: 1,
      feedUrl: 'https://example.com/feed.json',
      lastCheckAt: twoHoursAgo.toISOString(),
    };
    await writeFile(join(tmpDir, 'metadata.json'), JSON.stringify(meta));
    // 1 day threshold — 2 hours is fresh
    expect(isFeedStale(1, tmpDir)).toBe(false);
    // 0.01 day (~14 minutes) threshold — 2 hours is stale
    expect(isFeedStale(0.01, tmpDir)).toBe(true);
  });

  it('returns false for malformed metadata (cannot determine staleness)', async () => {
    await writeFile(join(tmpDir, 'metadata.json'), '{"invalid json');
    expect(isFeedStale(7, tmpDir)).toBe(false);
  });
});

// ── loadCachedFeed ──────────────────────────────────────────────────

describe('loadCachedFeed', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), 'vaso-cache-'));
  });

  afterEach(async () => {
    await rm(tmpDir, { recursive: true, force: true });
  });

  it('returns null when no files exist', async () => {
    expect(await loadCachedFeed(tmpDir, testPublicKeyPem)).toBeNull();
  });

  it('returns parsed data for valid cached feed', async () => {
    const feed = makeFeed({ data: { c2Ips: ['10.0.0.1'] } });
    const feedBytes = Buffer.from(JSON.stringify(feed));
    const sig = signFeed(feedBytes);

    await writeFile(join(tmpDir, 'feed.json'), feedBytes);
    await writeFile(join(tmpDir, 'feed.json.sig'), sig);

    const result = await loadCachedFeed(tmpDir, testPublicKeyPem);
    expect(result).not.toBeNull();
    expect(result!.c2Ips).toEqual(['10.0.0.1']);
  });

  it('returns null and deletes files on tampered feed', async () => {
    const feed = makeFeed({ data: { c2Ips: ['10.0.0.1'] } });
    const feedBytes = Buffer.from(JSON.stringify(feed));
    const sig = signFeed(feedBytes);

    // Write valid sig but tampered data
    const tampered = Buffer.from(JSON.stringify(makeFeed({ data: { c2Ips: ['TAMPERED'] } })));
    await writeFile(join(tmpDir, 'feed.json'), tampered);
    await writeFile(join(tmpDir, 'feed.json.sig'), sig);

    const result = await loadCachedFeed(tmpDir, testPublicKeyPem);
    expect(result).toBeNull();

    // Files should be deleted
    const feedExists = await readFile(join(tmpDir, 'feed.json')).then(() => true).catch(() => false);
    expect(feedExists).toBe(false);
  });
});

// ── fetchAndUpdateFeed ──────────────────────────────────────────────

describe('fetchAndUpdateFeed', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), 'vaso-fetch-'));
  });

  afterEach(async () => {
    await rm(tmpDir, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it('succeeds with valid feed and signature', async () => {
    const feed = makeFeed({
      meta: { version: 1, timestamp: new Date().toISOString(), description: 'test' },
      data: { c2Ips: ['10.0.0.1'], maliciousDomains: ['evil.test'] },
    });
    const feedBytes = Buffer.from(JSON.stringify(feed));
    const sig = signFeed(feedBytes);

    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
      if (url.endsWith('.sig')) {
        return Promise.resolve({ ok: true, text: () => Promise.resolve(sig), arrayBuffer: () => Promise.resolve(Buffer.from(sig).buffer) });
      }
      return Promise.resolve({ ok: true, text: () => Promise.resolve(feedBytes.toString()), arrayBuffer: () => Promise.resolve(feedBytes.buffer.slice(feedBytes.byteOffset, feedBytes.byteOffset + feedBytes.byteLength)) });
    }));

    const result = await fetchAndUpdateFeed({
      feedUrl: 'https://example.com/feed.json',
      feedDir: tmpDir,
      publicKeyPem: testPublicKeyPem,
      force: true,
    });

    expect(result.success).toBe(true);
    expect(result.feedVersion).toBe(1);
    expect(result.newIndicators?.c2Ips).toBe(1);
    expect(result.newIndicators?.maliciousDomains).toBe(1);

    // Files should be persisted
    const savedFeed = await readFile(join(tmpDir, 'feed.json'), 'utf-8');
    expect(JSON.parse(savedFeed).meta.version).toBe(1);
  });

  it('returns graceful error on fetch failure', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('Network error')));

    const result = await fetchAndUpdateFeed({
      feedUrl: 'https://example.com/feed.json',
      feedDir: tmpDir,
      publicKeyPem: testPublicKeyPem,
      force: true,
    });

    expect(result.success).toBe(false);
    expect(result.message).toContain('Network error');
  });

  it('rejects bad signature', async () => {
    const feed = makeFeed({ meta: { version: 1, timestamp: new Date().toISOString(), description: 'test' }, data: {} });
    const feedBytes = Buffer.from(JSON.stringify(feed));
    const badSig = Buffer.alloc(64).toString('base64');

    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
      if (url.endsWith('.sig')) {
        return Promise.resolve({ ok: true, text: () => Promise.resolve(badSig), arrayBuffer: () => Promise.resolve(Buffer.from(badSig).buffer) });
      }
      return Promise.resolve({ ok: true, text: () => Promise.resolve(feedBytes.toString()), arrayBuffer: () => Promise.resolve(feedBytes.buffer.slice(feedBytes.byteOffset, feedBytes.byteOffset + feedBytes.byteLength)) });
    }));

    const result = await fetchAndUpdateFeed({
      feedUrl: 'https://example.com/feed.json',
      feedDir: tmpDir,
      publicKeyPem: testPublicKeyPem,
      force: true,
    });

    expect(result.success).toBe(false);
    expect(result.message).toContain('signature verification failed');
  });

  it('skips old version unless forced', async () => {
    // Write metadata with version 5
    const meta: IOCFeedMetadata = {
      lastUpdated: new Date().toISOString(),
      feedVersion: 5,
      feedUrl: 'https://example.com/feed.json',
      lastCheckAt: new Date(0).toISOString(), // stale to pass staleness check
    };
    await writeFile(join(tmpDir, 'metadata.json'), JSON.stringify(meta));

    // Feed has version 3 (older)
    const feed = makeFeed({ meta: { version: 3, timestamp: new Date().toISOString(), description: 'old' }, data: {} });
    const feedBytes = Buffer.from(JSON.stringify(feed));
    const sig = signFeed(feedBytes);

    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
      if (url.endsWith('.sig')) {
        return Promise.resolve({ ok: true, text: () => Promise.resolve(sig), arrayBuffer: () => Promise.resolve(Buffer.from(sig).buffer) });
      }
      return Promise.resolve({ ok: true, text: () => Promise.resolve(feedBytes.toString()), arrayBuffer: () => Promise.resolve(feedBytes.buffer.slice(feedBytes.byteOffset, feedBytes.byteOffset + feedBytes.byteLength)) });
    }));

    const result = await fetchAndUpdateFeed({
      feedUrl: 'https://example.com/feed.json',
      feedDir: tmpDir,
      publicKeyPem: testPublicKeyPem,
    });

    expect(result.success).toBe(true);
    expect(result.message).toContain('not newer');
  });

  it('first-time fetch proceeds without force when no metadata exists', async () => {
    const feed = makeFeed({
      meta: { version: 1, timestamp: new Date().toISOString(), description: 'test' },
      data: { c2Ips: ['10.0.0.1'] },
    });
    const feedBytes = Buffer.from(JSON.stringify(feed));
    const sig = signFeed(feedBytes);

    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
      if (url.endsWith('.sig')) {
        return Promise.resolve({ ok: true, text: () => Promise.resolve(sig), arrayBuffer: () => Promise.resolve(Buffer.from(sig).buffer) });
      }
      return Promise.resolve({ ok: true, text: () => Promise.resolve(feedBytes.toString()), arrayBuffer: () => Promise.resolve(feedBytes.buffer.slice(feedBytes.byteOffset, feedBytes.byteOffset + feedBytes.byteLength)) });
    }));

    const result = await fetchAndUpdateFeed({
      feedUrl: 'https://example.com/feed.json',
      feedDir: tmpDir,
      publicKeyPem: testPublicKeyPem,
    });

    expect(result.success).toBe(true);
    expect(result.feedVersion).toBe(1);
  });

  it('skips update when feed is not stale', async () => {
    // Write fresh metadata
    const meta: IOCFeedMetadata = {
      lastUpdated: new Date().toISOString(),
      feedVersion: 1,
      feedUrl: 'https://example.com/feed.json',
      lastCheckAt: new Date().toISOString(),
    };
    await writeFile(join(tmpDir, 'metadata.json'), JSON.stringify(meta));

    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const result = await fetchAndUpdateFeed({
      feedUrl: 'https://example.com/feed.json',
      feedDir: tmpDir,
      publicKeyPem: testPublicKeyPem,
    });

    expect(result.success).toBe(true);
    expect(result.message).toContain('up to date');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('force bypasses staleness check', async () => {
    // Write fresh metadata
    const meta: IOCFeedMetadata = {
      lastUpdated: new Date().toISOString(),
      feedVersion: 1,
      feedUrl: 'https://example.com/feed.json',
      lastCheckAt: new Date().toISOString(),
    };
    await writeFile(join(tmpDir, 'metadata.json'), JSON.stringify(meta));

    const feed = makeFeed({ meta: { version: 2, timestamp: new Date().toISOString(), description: 'new' }, data: { c2Ips: ['10.0.0.1'] } });
    const feedBytes = Buffer.from(JSON.stringify(feed));
    const sig = signFeed(feedBytes);

    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
      if (url.endsWith('.sig')) {
        return Promise.resolve({ ok: true, text: () => Promise.resolve(sig), arrayBuffer: () => Promise.resolve(Buffer.from(sig).buffer) });
      }
      return Promise.resolve({ ok: true, text: () => Promise.resolve(feedBytes.toString()), arrayBuffer: () => Promise.resolve(feedBytes.buffer.slice(feedBytes.byteOffset, feedBytes.byteOffset + feedBytes.byteLength)) });
    }));

    const result = await fetchAndUpdateFeed({
      feedUrl: 'https://example.com/feed.json',
      feedDir: tmpDir,
      publicKeyPem: testPublicKeyPem,
      force: true,
    });

    expect(result.success).toBe(true);
    expect(result.feedVersion).toBe(2);
  });
});

// ── initIOCDatabase integration ─────────────────────────────────────

describe('initIOCDatabase', () => {
  beforeEach(() => {
    reloadIOCDatabase();
  });

  it('returns bundled data when no cache exists', async () => {
    const bundled = buildBundledDatabase();
    await initIOCDatabase();
    const db = getIOCDatabase();
    expect(db.c2Ips).toEqual(bundled.c2Ips);
  });

  it('is idempotent', async () => {
    await initIOCDatabase();
    const db1 = getIOCDatabase();
    await initIOCDatabase();
    const db2 = getIOCDatabase();
    expect(db2).toBe(db1); // same reference
  });

  it('resets via reloadIOCDatabase', async () => {
    await initIOCDatabase();
    const db1 = getIOCDatabase();
    reloadIOCDatabase();
    const db2 = getIOCDatabase();
    expect(db2).not.toBe(db1);
  });
});
