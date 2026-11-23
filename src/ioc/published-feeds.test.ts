import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { verify, createPublicKey } from 'node:crypto';
import { IOC_FEED_PUBLIC_KEY } from './public-key.js';
import { satisfies, parseSemVer, constraintBranches } from '../core/semver.js';
import type { IOCFeed, IOCFeedData } from './feed-types.js';
import type { AdvisoryFeed } from '../advisory/advisory-types.js';
import { LIBRARY_ADVISORIES } from '../advisory/library-advisories.js';
import { BUNDLED_ADVISORY_FEED_VERSION, buildBundledAdvisoryDatabase } from '../advisory/database.js';
import { buildBundledDatabase } from './database.js';

/**
 * Guards on the *published* feed artifacts in feeds/ — the hand-edited JSON
 * that `vaso update` clients actually consume. Catches the two silent failure
 * modes of the publish flow: editing a feed without re-signing it, and a
 * typo'd version constraint that never matches anything.
 */

const feedPath = (name: string) => fileURLToPath(new URL(`../../feeds/${name}`, import.meta.url));
const readFeed = <T>(name: string): T => JSON.parse(readFileSync(feedPath(name), 'utf-8')) as T;

const SEVERITIES = new Set(['critical', 'warning', 'info']);
const IOC_FEED_KEYS = new Set<keyof IOCFeedData>([
  'c2Ips',
  'maliciousDomains',
  'fileHashes',
  'maliciousPublishers',
  'maliciousSkillPatterns',
  'trustedSkillNames',
  'trustedMCPPackages',
  'binaryPatterns',
]);

describe.each(['feed.json', 'advisory-feed.json'])('%s', (name) => {
  const feed = readFeed<IOCFeed | AdvisoryFeed>(name);

  it('has well-formed meta', () => {
    expect(Number.isInteger(feed.meta.version)).toBe(true);
    expect(feed.meta.version).toBeGreaterThanOrEqual(1);
    expect(Number.isNaN(Date.parse(feed.meta.timestamp))).toBe(false);
    expect(feed.meta.description.length).toBeGreaterThan(0);
  });

  it('signature verifies against the pinned public key', () => {
    const key = createPublicKey(IOC_FEED_PUBLIC_KEY);
    const sig = Buffer.from(readFileSync(feedPath(`${name}.sig`), 'utf-8').trim(), 'base64');
    expect(sig.length).toBe(64);
    expect(verify(null, readFileSync(feedPath(name)), key, sig)).toBe(true);
  });
});

describe('feed.json data', () => {
  const feed = readFeed<IOCFeed>('feed.json');

  it('only uses known IOCFeedData keys', () => {
    for (const key of Object.keys(feed.data)) {
      expect(IOC_FEED_KEYS.has(key as keyof IOCFeedData), `unknown feed data key "${key}"`).toBe(true);
    }
  });

  it('domains are bare hostnames', () => {
    for (const domain of feed.data.maliciousDomains ?? []) {
      expect(domain).toMatch(/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/);
    }
  });
});

describe('advisory-feed.json data', () => {
  const feed = readFeed<AdvisoryFeed>('advisory-feed.json');
  const advisories = feed.data.advisories;

  it('advisory ids are unique', () => {
    const ids = advisories.map((a) => a.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it.each(advisories.map((a) => [a.id, a] as const))('%s is well-formed', (_id, adv) => {
    expect(adv.title.length).toBeGreaterThan(0);
    expect(adv.description.length).toBeGreaterThan(0);
    expect(SEVERITIES.has(adv.severity)).toBe(true);
    expect(adv.published).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(adv.affectedVersions.length).toBeGreaterThan(0);

    // Every version token in every constraint must parse — a typo'd version
    // makes satisfies() silently return false forever.
    const constraints = [adv.affectedVersions, adv.affectedDependency?.versionConstraint].filter(
      (c): c is string => Boolean(c)
    );
    for (const constraint of constraints) {
      // `||` separates one range per release line.
      for (const branch of constraintBranches(constraint)) {
        for (const token of branch.split(/\s+/)) {
          const version = token.replace(/^(>=|<=|>|<|=)/, '');
          expect(parseSemVer(version), `unparseable version in "${constraint}"`).not.toBeNull();
        }
      }
    }

    // A fixed version must not be flagged by its own advisory; a multi-line
    // advisory lists every line's fix, comma-separated.
    if (adv.fixedVersion && adv.affectedDependency) {
      for (const fixed of adv.fixedVersion.split(', ')) {
        expect(parseSemVer(fixed), `unparseable fixedVersion "${adv.fixedVersion}"`).not.toBeNull();
        expect(satisfies(fixed, adv.affectedDependency.versionConstraint)).toBe(false);
      }
    }
  });
});

describe('advisory feed v2 known-version spot checks', () => {
  const feed = readFeed<AdvisoryFeed>('advisory-feed.json');
  const constraint = (id: string) => {
    const adv = feed.data.advisories.find((a) => a.id === id);
    expect(adv?.affectedDependency, id).toBeTruthy();
    return adv!.affectedDependency!.versionConstraint;
  };

  it('flags known-vulnerable versions', () => {
    expect(satisfies('0.1.15', constraint('CVE-2025-6514'))).toBe(true);
    expect(satisfies('0.14.0', constraint('CVE-2025-49596'))).toBe(true);
    expect(satisfies('0.6.2', constraint('CVE-2025-53109'))).toBe(true);
    expect(satisfies('2025.3.28', constraint('CVE-2025-53109'))).toBe(true);
    expect(satisfies('2025.1.14', constraint('CVE-2025-53110'))).toBe(true);
    expect(satisfies('1.0.16', constraint('VASO-MAL-2025-001'))).toBe(true);
  });

  it('clears fixed / unaffected versions', () => {
    expect(satisfies('0.1.16', constraint('CVE-2025-6514'))).toBe(false);
    expect(satisfies('0.14.1', constraint('CVE-2025-49596'))).toBe(false);
    expect(satisfies('2025.7.1', constraint('CVE-2025-53109'))).toBe(false);
    expect(satisfies('2025.7.29', constraint('CVE-2025-53110'))).toBe(false);
    expect(satisfies('1.0.15', constraint('VASO-MAL-2025-001'))).toBe(false);
  });
});

describe('advisory feed mirrors the bundled library advisories', () => {
  const feed = readFeed<AdvisoryFeed>('advisory-feed.json');
  const byId = new Map(feed.data.advisories.map((a) => [a.id, a]));

  it.each(LIBRARY_ADVISORIES.map((a) => [a.id, a] as const))('%s is in the feed, identical to the bundle', (id, adv) => {
    // The feed overrides a bundled advisory with the same id; they must agree.
    expect(byId.get(id)).toEqual(adv);
  });
});

describe('bundled advisories carry every published feed advisory', () => {
  // Offline installs (no `vaso update`) see only the bundle, so every advisory
  // the signed feed publishes must also ship in it — and agree with it, since
  // the feed overrides a bundled advisory with the same id.
  const feed = readFeed<AdvisoryFeed>('advisory-feed.json');
  const bundled = new Map(buildBundledAdvisoryDatabase().advisories.map((a) => [a.id, a]));

  it('BUNDLED_ADVISORY_FEED_VERSION is the published feed version', () => {
    // A cached feed not newer than this is ignored: bump it with every feed
    expect(BUNDLED_ADVISORY_FEED_VERSION).toBe(feed.meta.version);
  });

  it('no feed advisory is missing from the bundle', () => {
    expect(feed.data.advisories.map((a) => a.id).filter((id) => !bundled.has(id))).toEqual([]);
  });

  it.each(feed.data.advisories.map((a) => [a.id, a] as const))('%s: bundled copy matches the feed', (id, adv) => {
    expect(bundled.get(id)).toEqual(adv);
  });
});

describe('the published advisory feed carries every bundled advisory', () => {
  // The reverse direction: installs on an older release learn new advisories
  // only from the feed, so a bundled advisory must be published too. Bundle-only
  // entries predate every supported release (bundled since v0.4.13 or earlier).
  const BUNDLE_ONLY = new Set(['CVE-2026-0755', 'VASO-CFG-2026-001']);
  const published = new Set(readFeed<AdvisoryFeed>('advisory-feed.json').data.advisories.map((a) => a.id));

  it('no bundled advisory is missing from the feed', () => {
    const missing = buildBundledAdvisoryDatabase().advisories.map((a) => a.id).filter((id) => !published.has(id) && !BUNDLE_ONLY.has(id));
    expect(missing).toEqual([]);
  });

  it('bundle-only exemptions are still bundle-only', () => {
    for (const id of BUNDLE_ONLY) expect(published.has(id), `${id} is published now; drop it from BUNDLE_ONLY`).toBe(false);
  });
});

describe('bundled IOC data carries every published feed indicator', () => {
  // Same contract as the advisories: offline installs see only the bundle, so
  // every indicator the signed IOC feed publishes must ship in it too.
  const feed = readFeed<IOCFeed>('feed.json');
  const db = buildBundledDatabase();
  const stringKeys = [
    'c2Ips',
    'maliciousDomains',
    'fileHashes',
    'maliciousPublishers',
    'trustedSkillNames',
    'trustedMCPPackages',
  ] as const;

  it.each(stringKeys)('no feed %s entry is missing from the bundle', (key) => {
    const bundled = new Set(db[key]);
    expect((feed.data[key] ?? []).filter((v) => !bundled.has(v))).toEqual([]);
  });

  // Threat indicators go both ways: an install on an older release gets new
  // ones only from the feed. Allowlists and patterns are code — not mirrored.
  it.each(['c2Ips', 'maliciousDomains', 'fileHashes', 'maliciousPublishers'] as const)(
    'no bundled %s entry is missing from the feed',
    (key) => {
      const published = new Set(feed.data[key] ?? []);
      expect(db[key].filter((v) => !published.has(v))).toEqual([]);
    }
  );

  it('no feed maliciousSkillPatterns entry is missing from the bundle', () => {
    const bundled = new Set(db.maliciousSkillPatterns.map((re) => `${re.source}/${re.flags}`));
    const missing = (feed.data.maliciousSkillPatterns ?? []).filter(
      (p) => !bundled.has(`${new RegExp(p.source, p.flags).source}/${p.flags ?? ''}`)
    );
    expect(missing).toEqual([]);
  });

  it('no feed binaryPatterns entry is missing from the bundle', () => {
    const key = (type: string, pattern: string) => `${type}:${pattern}`;
    const bundled = new Set(
      db.binaryPatterns.map((b) =>
        key(b.type, Buffer.isBuffer(b.pattern) ? b.pattern.toString('hex') : (b.pattern as RegExp).source)
      )
    );
    const missing = (feed.data.binaryPatterns ?? []).filter(
      (b) => !bundled.has(key(b.type, b.type === 'buffer' ? b.pattern.toLowerCase() : b.pattern))
    );
    expect(missing).toEqual([]);
  });
});
