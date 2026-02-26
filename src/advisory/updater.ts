import { readFileSync } from 'node:fs';
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

export const DEFAULT_ADVISORY_FEED_URL =
  'https://raw.githubusercontent.com/vulnex/vaso-feeds/main/advisory-feed.json';

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
  try {
    const raw = readFileSync(join(metadataDir, METADATA_FILE), 'utf-8');
    const meta: AdvisoryFeedMetadata = JSON.parse(raw);
    const lastCheck = new Date(meta.lastCheckAt).getTime();
    if (isNaN(lastCheck)) return true;
    const ageMs = Date.now() - lastCheck;
    return ageMs > thresholdDays * 24 * 60 * 60 * 1000;
  } catch {
    return true;
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
  force?: boolean;
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

  if (!force && !isAdvisoryFeedStale(DEFAULT_STALENESS_DAYS, feedDir)) {
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
    return { success: false, message: `Failed to fetch advisory feed: ${msg}` };
  }

  if (!feedResponse.ok) {
    return { success: false, message: `Advisory feed fetch failed: HTTP ${feedResponse.status}` };
  }
  if (!sigResponse.ok) {
    return { success: false, message: `Advisory signature fetch failed: HTTP ${sigResponse.status}` };
  }

  const feedBytes = Buffer.from(await feedResponse.arrayBuffer());
  const sigBase64 = (await sigResponse.text()).trim();

  let feed: AdvisoryFeed;
  try {
    feed = JSON.parse(feedBytes.toString('utf-8'));
    if (!feed.meta || typeof feed.meta.version !== 'number' || !feed.data) {
      return { success: false, message: 'Invalid advisory feed format.' };
    }
  } catch {
    return { success: false, message: 'Invalid advisory feed JSON.' };
  }

  if (feed.meta.version <= currentVersion && !force) {
    return {
      success: true,
      message: `Advisory feed version ${feed.meta.version} is not newer than cached version ${currentVersion}.`,
    };
  }

  if (!verifyFeedSignature(feedBytes, sigBase64, publicKeyPem)) {
    return { success: false, message: 'Advisory feed signature verification failed.' };
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
