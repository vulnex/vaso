import { verify as cryptoVerify, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mkdir, readFile, writeFile, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { IOC_FEED_PUBLIC_KEY, DEFAULT_FEED_URL, DEFAULT_STALENESS_DAYS } from './public-key.js';
import type { BinaryPattern, IOCDatabase } from './database.js';
import type {
  IOCFeed,
  IOCFeedData,
  IOCFeedMetadata,
  SerializedBinaryPattern,
  SerializedRegExp,
  UpdateResult,
} from './feed-types.js';

const IOC_DIR = join(homedir(), '.vaso', 'ioc');
const FEED_FILE = 'feed.json';
const SIG_FILE = 'feed.json.sig';
const METADATA_FILE = 'metadata.json';
const FETCH_TIMEOUT_MS = 15_000;

// ── Signature verification ──────────────────────────────────────────

export function verifyFeedSignature(
  feedBytes: Buffer,
  sigBase64: string,
  publicKeyPem: string = IOC_FEED_PUBLIC_KEY,
): boolean {
  try {
    const sig = Buffer.from(sigBase64, 'base64');
    if (sig.length !== 64) return false;
    const keyObject = createPublicKey(publicKeyPem);
    return cryptoVerify(null, feedBytes, keyObject, sig);
  } catch {
    return false;
  }
}

// ── Deserialization helpers ─────────────────────────────────────────

export function deserializePatterns(serialized: SerializedRegExp[]): RegExp[] {
  return serialized.map((s) => new RegExp(s.source, s.flags ?? ''));
}

export function deserializeBinaryPatterns(serialized: SerializedBinaryPattern[]): BinaryPattern[] {
  return serialized.map((s) => {
    if (s.type === 'buffer') {
      return { name: s.name, pattern: Buffer.from(s.pattern, 'hex'), type: 'buffer' as const };
    }
    return { name: s.name, pattern: new RegExp(s.pattern, s.flags ?? ''), type: 'regex' as const };
  });
}

// ── Merge logic ─────────────────────────────────────────────────────

function dedupeStrings(base: string[], additions: string[]): string[] {
  const set = new Set(base);
  for (const item of additions) set.add(item);
  return [...set];
}

function dedupeRegExps(base: RegExp[], additions: RegExp[]): RegExp[] {
  const seen = new Set(base.map((r) => `${r.source}|||${r.flags}`));
  const result = [...base];
  for (const r of additions) {
    const key = `${r.source}|||${r.flags}`;
    if (!seen.has(key)) {
      seen.add(key);
      result.push(r);
    }
  }
  return result;
}

function dedupeBinaryPatterns(base: BinaryPattern[], additions: BinaryPattern[]): BinaryPattern[] {
  const seen = new Set(base.map((p) => `${p.name}|||${p.type}`));
  const result = [...base];
  for (const p of additions) {
    const key = `${p.name}|||${p.type}`;
    if (!seen.has(key)) {
      seen.add(key);
      result.push(p);
    }
  }
  return result;
}

export function mergeFeedIntoDatabase(bundled: IOCDatabase, feedData: IOCFeedData): IOCDatabase {
  return {
    c2Ips: dedupeStrings(bundled.c2Ips, feedData.c2Ips ?? []),
    maliciousDomains: dedupeStrings(bundled.maliciousDomains, feedData.maliciousDomains ?? []),
    fileHashes: dedupeStrings(bundled.fileHashes, feedData.fileHashes ?? []),
    maliciousPublishers: dedupeStrings(bundled.maliciousPublishers, feedData.maliciousPublishers ?? []),
    maliciousSkillPatterns: dedupeRegExps(
      bundled.maliciousSkillPatterns,
      feedData.maliciousSkillPatterns ? deserializePatterns(feedData.maliciousSkillPatterns) : [],
    ),
    trustedSkillNames: dedupeStrings(bundled.trustedSkillNames, feedData.trustedSkillNames ?? []),
    trustedMCPPackages: dedupeStrings(bundled.trustedMCPPackages, feedData.trustedMCPPackages ?? []),
    binaryPatterns: dedupeBinaryPatterns(
      bundled.binaryPatterns,
      feedData.binaryPatterns ? deserializeBinaryPatterns(feedData.binaryPatterns) : [],
    ),
  };
}

// ── Staleness check ─────────────────────────────────────────────────

export function isFeedStale(thresholdDays: number = DEFAULT_STALENESS_DAYS, metadataDir: string = IOC_DIR): boolean {
  try {
    const raw = readFileSync(join(metadataDir, METADATA_FILE), 'utf-8');
    const meta: IOCFeedMetadata = JSON.parse(raw);
    const lastCheck = new Date(meta.lastCheckAt).getTime();
    if (isNaN(lastCheck)) return true;
    const ageMs = Date.now() - lastCheck;
    return ageMs > thresholdDays * 24 * 60 * 60 * 1000;
  } catch {
    return true; // no metadata = stale
  }
}

// ── Cached feed loader ──────────────────────────────────────────────

export async function loadCachedFeed(
  feedDir: string = IOC_DIR,
  publicKeyPem: string = IOC_FEED_PUBLIC_KEY,
): Promise<IOCFeedData | null> {
  try {
    const feedPath = join(feedDir, FEED_FILE);
    const sigPath = join(feedDir, SIG_FILE);

    let feedBytes: Buffer;
    let sigContent: string;
    try {
      feedBytes = await readFile(feedPath);
      sigContent = (await readFile(sigPath, 'utf-8')).trim();
    } catch {
      return null; // files don't exist
    }

    // Re-verify signature on every load (catches local tampering)
    if (!verifyFeedSignature(feedBytes, sigContent, publicKeyPem)) {
      // Tampered — delete both files
      await unlink(feedPath).catch(() => {});
      await unlink(sigPath).catch(() => {});
      return null;
    }

    const feed: IOCFeed = JSON.parse(feedBytes.toString('utf-8'));
    return feed.data;
  } catch {
    return null;
  }
}

// ── Fetch and update ────────────────────────────────────────────────

export interface FetchOptions {
  feedUrl?: string;
  force?: boolean;
  feedDir?: string;
  publicKeyPem?: string;
}

export async function fetchAndUpdateFeed(options: FetchOptions = {}): Promise<UpdateResult> {
  const feedUrl = options.feedUrl ?? DEFAULT_FEED_URL;
  const feedDir = options.feedDir ?? IOC_DIR;
  const publicKeyPem = options.publicKeyPem ?? IOC_FEED_PUBLIC_KEY;
  const force = options.force ?? false;

  // Ensure directory exists
  await mkdir(feedDir, { recursive: true });

  // Unless forced, check staleness
  if (!force && !isFeedStale(DEFAULT_STALENESS_DAYS, feedDir)) {
    return { success: true, message: 'Feed is up to date (not stale).' };
  }

  // Load current metadata for version comparison
  let currentVersion = 0;
  try {
    const metaRaw = await readFile(join(feedDir, METADATA_FILE), 'utf-8');
    const meta: IOCFeedMetadata = JSON.parse(metaRaw);
    currentVersion = meta.feedVersion;
  } catch {
    // No existing metadata
  }

  // Fetch feed and signature
  let feedResponse: Response;
  let sigResponse: Response;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      [feedResponse, sigResponse] = await Promise.all([
        fetch(feedUrl, { signal: controller.signal }),
        fetch(feedUrl + '.sig', { signal: controller.signal }),
      ]);
    } finally {
      clearTimeout(timeout);
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, message: `Failed to fetch feed: ${msg}` };
  }

  if (!feedResponse.ok) {
    return { success: false, message: `Feed fetch failed: HTTP ${feedResponse.status}` };
  }
  if (!sigResponse.ok) {
    return { success: false, message: `Signature fetch failed: HTTP ${sigResponse.status}` };
  }

  const feedBytes = Buffer.from(await feedResponse.arrayBuffer());
  const sigBase64 = (await sigResponse.text()).trim();

  // Parse and validate structure
  let feed: IOCFeed;
  try {
    feed = JSON.parse(feedBytes.toString('utf-8'));
    if (!feed.meta || typeof feed.meta.version !== 'number' || !feed.data) {
      return { success: false, message: 'Invalid feed format: missing meta or data fields.' };
    }
  } catch {
    return { success: false, message: 'Invalid feed JSON.' };
  }

  // Reject downgrades
  if (feed.meta.version <= currentVersion && !force) {
    return {
      success: true,
      message: `Feed version ${feed.meta.version} is not newer than cached version ${currentVersion}.`,
    };
  }

  // Verify signature
  if (!verifyFeedSignature(feedBytes, sigBase64, publicKeyPem)) {
    return { success: false, message: 'Feed signature verification failed.' };
  }

  // Persist feed, signature, and metadata
  await writeFile(join(feedDir, FEED_FILE), feedBytes);
  await writeFile(join(feedDir, SIG_FILE), sigBase64);

  const metadata: IOCFeedMetadata = {
    lastUpdated: new Date().toISOString(),
    feedVersion: feed.meta.version,
    feedUrl,
    lastCheckAt: new Date().toISOString(),
  };
  await writeFile(join(feedDir, METADATA_FILE), JSON.stringify(metadata, null, 2));

  // Count new indicators
  const data = feed.data;
  const newIndicators = {
    c2Ips: data.c2Ips?.length ?? 0,
    maliciousDomains: data.maliciousDomains?.length ?? 0,
    fileHashes: data.fileHashes?.length ?? 0,
    maliciousPublishers: data.maliciousPublishers?.length ?? 0,
    maliciousSkillPatterns: data.maliciousSkillPatterns?.length ?? 0,
    trustedSkillNames: data.trustedSkillNames?.length ?? 0,
    trustedMCPPackages: data.trustedMCPPackages?.length ?? 0,
    binaryPatterns: data.binaryPatterns?.length ?? 0,
  };

  return {
    success: true,
    message: `Feed updated to version ${feed.meta.version}.`,
    newIndicators,
    feedVersion: feed.meta.version,
  };
}
