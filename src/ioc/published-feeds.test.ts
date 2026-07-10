import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { verify, createPublicKey } from 'node:crypto';
import { IOC_FEED_PUBLIC_KEY } from './public-key.js';
import { satisfies, parseSemVer } from '../core/semver.js';
import type { IOCFeed, IOCFeedData } from './feed-types.js';
import type { AdvisoryFeed } from '../advisory/advisory-types.js';

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
      for (const token of constraint.trim().split(/\s+/)) {
        const version = token.replace(/^(>=|<=|>|<|=)/, '');
        expect(parseSemVer(version), `unparseable version in "${constraint}"`).not.toBeNull();
      }
    }

    // A fixed version must not be flagged by its own advisory.
    if (adv.fixedVersion && adv.affectedDependency) {
      expect(satisfies(adv.fixedVersion, adv.affectedDependency.versionConstraint)).toBe(false);
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
