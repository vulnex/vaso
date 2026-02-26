import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mergeAdvisoryFeed, isAdvisoryFeedStale } from './updater.js';
import { buildBundledAdvisoryDatabase } from './database.js';
import type { Advisory, AdvisoryFeedData } from './advisory-types.js';

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
  it('returns true when metadata dir does not exist', () => {
    expect(isAdvisoryFeedStale(7, '/nonexistent/path')).toBe(true);
  });
});
