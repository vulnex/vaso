import { existsSync, readFileSync } from 'node:fs';
import { readBodyCapped } from '../core/http-body.js';
import { mkdir, readFile, writeFile, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { verifyFeedSignature } from '../ioc/updater.js';
import { IOC_FEED_PUBLIC_KEY, DEFAULT_STALENESS_DAYS } from '../ioc/public-key.js';
import type {
  Advisory,
  AdvisoryFeed,
  AdvisoryFeedData,
  AdvisoryFeedMetadata,
  AdvisoryUpdateResult,
} from './advisory-types.js';
import type { AdvisoryDatabase } from './database.js';

const ADVISORY_DIR = join(homedir(), '.vaso', 'advisory');
const FEED_FILE = 'advisory-feed.json';
const SIG_FILE = 'advisory-feed.json.sig';
const METADATA_FILE = 'metadata.json';
const FETCH_TIMEOUT_MS = 15_000;
/** Published feeds are well under 1 MiB; anything far larger is not a feed. */
const MAX_FEED_BYTES = 16 * 1024 * 1024;
/** A base64 Ed25519 signature is 88 bytes. */
const MAX_SIGNATURE_BYTES = 4096;

export const DEFAULT_ADVISORY_FEED_URL =
  'https://raw.githubusercontent.com/vulnex/vaso/main/feeds/advisory-feed.json';

// ── Merge logic ─────────────────────────────────────────────────────

export function mergeAdvisoryFeed(
  bundled: AdvisoryDatabase,
  feedData: AdvisoryFeedData,
): AdvisoryDatabase {
  const byId = new Map<string, Advisory>();

  // Bundled first
  for (const adv of bundled.advisories) {
    byId.set(adv.id, adv);
  }

  // Feed overrides bundled for same ID
  for (const adv of feedData.advisories) {
    byId.set(adv.id, adv);
  }

  return { advisories: [...byId.values()] };
}

// ── Staleness check ─────────────────────────────────────────────────

export function isAdvisoryFeedStale(
  thresholdDays: number = DEFAULT_STALENESS_DAYS,
  metadataDir: string = ADVISORY_DIR,
): boolean {
  let raw: string;
  try {
    raw = readFileSync(join(metadataDir, METADATA_FILE), 'utf-8');
  } catch {
    // No metadata file: user has never fetched a remote feed.
    // Treat as "not opted in" rather than stale — bundled data is the baseline.
    return false;
  }
  try {
    const meta: AdvisoryFeedMetadata = JSON.parse(raw);
    const lastCheck = new Date(meta.lastCheckAt).getTime();
    if (isNaN(lastCheck)) return false;
    const ageMs = Date.now() - lastCheck;
    return ageMs > thresholdDays * 24 * 60 * 60 * 1000;
  } catch {
    return false;
  }
}

// ── Cached feed loader ──────────────────────────────────────────────

export async function loadCachedAdvisoryFeed(
  feedDir: string = ADVISORY_DIR,
  publicKeyPem: string = IOC_FEED_PUBLIC_KEY,
): Promise<AdvisoryFeedData | null> {
  try {
    const feedPath = join(feedDir, FEED_FILE);
    const sigPath = join(feedDir, SIG_FILE);

    let feedBytes: Buffer;
    let sigContent: string;
    try {
      feedBytes = await readFile(feedPath);
      sigContent = (await readFile(sigPath, 'utf-8')).trim();
    } catch {
      return null;
    }

    if (!verifyFeedSignature(feedBytes, sigContent, publicKeyPem)) {
      await unlink(feedPath).catch(() => {});
      await unlink(sigPath).catch(() => {});
      // Bundled data still applies, but the user should know the update is gone
      console.error(`Warning: the cached advisory feed failed signature verification and was removed; run \`vaso update\` to re-install it.`);
      return null;
    }

    const feed: AdvisoryFeed = JSON.parse(feedBytes.toString('utf-8'));
    return feed.data;
  } catch {
    return null;
  }
}

// ── Fetch and update ────────────────────────────────────────────────

export interface AdvisoryFetchOptions {
  feedUrl?: string;
  /** Fetch even when the cached feed isn't stale. */
  force?: boolean;
  /** Re-install a feed of the same version as the cache (repairs a damaged
   *  cache). An older feed is never installed — that would roll back
   *  indicators with a replayed, validly signed old feed. */
  reinstall?: boolean;
  feedDir?: string;
  publicKeyPem?: string;
}

export async function fetchAndUpdateAdvisoryFeed(
  options: AdvisoryFetchOptions = {},
): Promise<AdvisoryUpdateResult> {
  const feedUrl = options.feedUrl ?? DEFAULT_ADVISORY_FEED_URL;
  const feedDir = options.feedDir ?? ADVISORY_DIR;
  const publicKeyPem = options.publicKeyPem ?? IOC_FEED_PUBLIC_KEY;
  const force = options.force ?? false;

  await mkdir(feedDir, { recursive: true });

  // A cached feed that is missing or fails its signature (deleted on load)
  // is no cache at all: fetch, and re-install even the same version
  const cacheUsable = (await loadCachedAdvisoryFeed(feedDir, publicKeyPem)) !== null;

  // Unless forced, skip when a cached feed exists and isn't stale.
  // (Missing metadata means no cache yet — proceed with the fetch.)
  if (!force && cacheUsable && existsSync(join(feedDir, METADATA_FILE)) && !isAdvisoryFeedStale(DEFAULT_STALENESS_DAYS, feedDir)) {
    return { success: true, message: 'Advisory feed is up to date (not stale).' };
  }

  let currentVersion = 0;
  try {
    const metaRaw = await readFile(join(feedDir, METADATA_FILE), 'utf-8');
    const meta: AdvisoryFeedMetadata = JSON.parse(metaRaw);
    currentVersion = meta.feedVersion;
  } catch {
    // No existing metadata
  }

  // Feed, then signature — one at a time, each body read before the next
  // request: two parallel responses with one body left unread can trip
  // undici when the server closes the connection.
  const get = async (url: string, maxBytes: number): Promise<{ status: number; body?: Buffer }> => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const res = await fetch(url, { signal: controller.signal });
      if (!res.ok) {
        await res.body?.cancel().catch(() => undefined);
        return { status: res.status };
      }
      return { status: res.status, body: await readBodyCapped(res, maxBytes) };
    } finally {
      clearTimeout(timeout);
    }
  };

  let feedBytes: Buffer;
  let sigBase64: string;
  try {
    const feedRes = await get(feedUrl, MAX_FEED_BYTES);
    if (!feedRes.body) return { success: false, message: `Advisory feed fetch failed: HTTP ${feedRes.status}` };
    const sigRes = await get(feedUrl + '.sig', MAX_SIGNATURE_BYTES);
    if (!sigRes.body) return { success: false, message: `Advisory signature fetch failed: HTTP ${sigRes.status}` };
    feedBytes = feedRes.body;
    sigBase64 = sigRes.body.toString('utf-8').trim();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, message: `Failed to fetch advisory feed: ${msg}` };
  }

  // Signature first: an unsigned response's version number is not trusted either
  if (!verifyFeedSignature(feedBytes, sigBase64, publicKeyPem)) {
    return { success: false, message: 'Advisory feed signature verification failed.' };
  }

  let feed: AdvisoryFeed;
  try {
    feed = JSON.parse(feedBytes.toString('utf-8'));
    if (!feed.meta || typeof feed.meta.version !== 'number' || !feed.data) {
      return { success: false, message: 'Invalid advisory feed format.' };
    }
  } catch {
    return { success: false, message: 'Invalid advisory feed JSON.' };
  }

  if (feed.meta.version < currentVersion || (feed.meta.version === currentVersion && !options.reinstall && cacheUsable)) {
    return {
      success: true,
      message: `Advisory feed version ${feed.meta.version} is not newer than cached version ${currentVersion}.`,
    };
  }

  await writeFile(join(feedDir, FEED_FILE), feedBytes);
  await writeFile(join(feedDir, SIG_FILE), sigBase64);

  const metadata: AdvisoryFeedMetadata = {
    lastUpdated: new Date().toISOString(),
    feedVersion: feed.meta.version,
    feedUrl,
    lastCheckAt: new Date().toISOString(),
  };
  await writeFile(join(feedDir, METADATA_FILE), JSON.stringify(metadata, null, 2));

  return {
    success: true,
    message: `Advisory feed updated to version ${feed.meta.version}.`,
    newAdvisories: feed.data.advisories.length,
    feedVersion: feed.meta.version,
  };
}
