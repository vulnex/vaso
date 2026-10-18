import { describe, it, expect, beforeEach } from 'vitest';
import {
  buildBundledAdvisoryDatabase,
  getAdvisoryDatabase,
  reloadAdvisoryDatabase,
} from './database.js';
import { parseSemVer, satisfies } from '../core/semver.js';
import { DEPRECATED_NPM_PACKAGES, LIBRARY_ADVISORIES } from './library-advisories.js';

describe('AdvisoryDatabase', () => {
  beforeEach(() => {
    reloadAdvisoryDatabase();
  });

  it('builds bundled database with advisory entries', () => {
    const db = buildBundledAdvisoryDatabase();
    expect(db.advisories.length).toBeGreaterThan(10);
  });

  it('only ships sourced advisories', () => {
    // Every CVE/GHSA entry cites its source. IDs in the CVE namespace must be
    // real records for the product described — early scaffolding shipped
    // invented CVE-2026-400xx entries whose IDs belong to unrelated products.
    // The removed IDs are listed exactly: the range also holds real records
    // (CVE-2026-40068 is a Claude Code trust-dialog bypass).
    const invented = new Set(['40001', '40002', '40003', '40010', '40011', '40020', '40030', '40031', '40040', '40041', '40050', '40051', '40100'].map((n) => `CVE-2026-${n}`));
    const db = buildBundledAdvisoryDatabase();
    for (const adv of db.advisories) {
      if (/^(CVE|GHSA)-/.test(adv.id)) expect(adv.reference, adv.id).toMatch(/^https:\/\//);
      expect(adv.reference ?? '').not.toContain('vulnex/vaso-advisories');
      expect(invented.has(adv.id), adv.id).toBe(false);
    }
  });

  it('has unique advisory IDs', () => {
    const db = buildBundledAdvisoryDatabase();
    const ids = db.advisories.map(a => a.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('all advisories have required fields', () => {
    const db = buildBundledAdvisoryDatabase();
    for (const adv of db.advisories) {
      expect(adv.id).toBeTruthy();
      expect(adv.title).toBeTruthy();
      expect(adv.agent).toBeTruthy();
      expect(adv.affectedVersions).toBeTruthy();
      expect(adv.severity).toBeTruthy();
      expect(adv.description).toBeTruthy();
      expect(adv.published).toBeTruthy();
    }
  });

  it('getAdvisoryDatabase returns bundled data when uninitialized', () => {
    const db = getAdvisoryDatabase();
    expect(db.advisories.length).toBeGreaterThan(0);
  });

  it('contains advisories with known exploits', () => {
    const db = buildBundledAdvisoryDatabase();
    const exploits = db.advisories.filter(a => a.exploitAvailable);
    expect(exploits.length).toBeGreaterThan(0);
  });

  it('contains dependency advisories', () => {
    const db = buildBundledAdvisoryDatabase();
    const deps = db.advisories.filter(a => a.affectedDependency);
    expect(deps.length).toBeGreaterThan(0);
  });

  it('contains config pattern advisories', () => {
    const db = buildBundledAdvisoryDatabase();
    const cfgs = db.advisories.filter(a => a.configPattern);
    expect(cfgs.length).toBeGreaterThan(0);
  });
});

// Devin CLI versions: calver 2026.M.D-N (N = build, ordered as a prerelease of
// 2026.M.D), then 3000.x.y. Ranges must hold across both schemes.
describe('Devin CLI advisories — version ranges', () => {
  const devin = buildBundledAdvisoryDatabase().advisories.filter(a => a.agent === 'devin');
  const affecting = (v: string) => devin.filter(a => satisfies(v, a.affectedVersions)).map(a => a.id).sort();

  it('ships the seven changelog-derived advisories', () => {
    expect(devin.map(a => a.id).sort()).toEqual([1, 2, 3, 4, 5, 6, 7].map(n => `VASO-DEVIN-2026-00${n}`));
  });

  it('flags nothing on the validated live version 3000.11.3', () => {
    expect(affecting('3000.11.3')).toEqual([]);
  });

  it('orders 2026.* builds below 3000.x and respects -N build boundaries', () => {
    expect(affecting('3000.3.26')).toEqual(['VASO-DEVIN-2026-001', 'VASO-DEVIN-2026-003', 'VASO-DEVIN-2026-004', 'VASO-DEVIN-2026-005']);
    expect(affecting('2026.4.8-3')).toContain('VASO-DEVIN-2026-006');
    expect(affecting('2026.4.9-0')).not.toContain('VASO-DEVIN-2026-006');
    expect(affecting('2026.5.26-0')).not.toContain('VASO-DEVIN-2026-007');
    expect(affecting('2026.5.20-2')).toContain('VASO-DEVIN-2026-007');
  });
});

describe('MCP SDK advisories', () => {
  const sdkAdvisories = buildBundledAdvisoryDatabase().advisories.filter(
    (a) => a.affectedDependency && ['@modelcontextprotocol/sdk', 'mcp'].includes(a.affectedDependency.name),
  );

  it('ships the GitHub-advisory set for both SDKs', () => {
    expect(sdkAdvisories.map((a) => a.id).sort()).toEqual([
      'CVE-2025-53365', 'CVE-2025-53366', 'CVE-2025-66414', 'CVE-2025-66416',
      'CVE-2026-0621', 'CVE-2026-104850', 'CVE-2026-25536', 'CVE-2026-52869', 'CVE-2026-52870', 'CVE-2026-59950',
    ]);
  });

  it.each(sdkAdvisories.map((a) => [a.id, a] as const))('%s: fix not flagged, usage pattern compiles', (_id, adv) => {
    expect(adv.fixedVersion).toBeTruthy();
    expect(satisfies(adv.fixedVersion!, adv.affectedDependency!.versionConstraint)).toBe(false);
    expect(() => new RegExp(adv.appliesWhen!.sourcePattern)).not.toThrow();
    // The Python SDK is `mcp` on PyPI — never an npm name.
    expect(adv.affectedDependency!.ecosystem ?? 'npm').toBe(adv.affectedDependency!.name === 'mcp' ? 'pypi' : 'npm');
  });

  it('has unique ids across the bundle', () => {
    const ids = buildBundledAdvisoryDatabase().advisories.map((a) => a.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  describe('library advisories', () => {
    it('are in the bundle', () => {
      const ids = new Set(buildBundledAdvisoryDatabase().advisories.map((a) => a.id));
      for (const adv of LIBRARY_ADVISORIES) expect(ids.has(adv.id), adv.id).toBe(true);
    });

    it.each(LIBRARY_ADVISORIES.map((a) => [a.id, a] as const))('%s: sourced, fixes not flagged, constraint parses', (_id, adv) => {
      expect(adv.reference).toMatch(/^https:\/\/github\.com\/advisories\/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/);
      const dep = adv.affectedDependency!;
      expect(dep.versionConstraint).toBe(adv.affectedVersions);
      for (const fixed of adv.fixedVersion?.split(', ') ?? []) {
        expect(parseSemVer(fixed), `fixedVersion ${fixed}`).not.toBeNull();
        expect(satisfies(fixed, dep.versionConstraint), `${fixed} is fixed`).toBe(false);
      }
      // Every comparator parses — one that doesn't makes the advisory match nothing.
      for (const token of dep.versionConstraint.split(/\s+/).filter((t) => t !== '||')) {
        expect(parseSemVer(token.replace(/^(>=|<=|>|<|=)/, '')), `${token} in ${dep.versionConstraint}`).not.toBeNull();
      }
      // PyPI names are PEP 503-normalized, as server-dependencies reads them.
      if (dep.ecosystem === 'pypi') expect(dep.name).toBe(dep.name.toLowerCase().replace(/[-_.]+/g, '-'));
      // agent 'mcp' keeps them out of agent-version checks (ADV-001/003/004).
      expect(adv.agent).toBe('mcp');
      expect(adv.exploitAvailable).toBeUndefined();
    });

    it('match the appsecco outdated-packages pins', () => {
      const hits = (name: string, version: string) =>
        LIBRARY_ADVISORIES.filter((a) => a.affectedDependency!.name === name && satisfies(version, a.affectedDependency!.versionConstraint)).map((a) => a.id);
      expect(hits('lodash', '4.17.20')).toEqual(['CVE-2021-23337', 'CVE-2020-28500']);
      expect(hits('ws', '7.4.6')).toEqual(['CVE-2024-37890']);
      expect(hits('minimist', '1.2.5')).toEqual(['CVE-2021-44906']);
      // Fixed in the pinned release: no finding.
      expect(hits('node-fetch', '2.6.7')).toEqual([]);
      expect(hits('lodash', '4.17.21')).toEqual([]);
    });

    it('lists only packages deprecated in every version', () => {
      expect(Object.keys(DEPRECATED_NPM_PACKAGES)).toContain('request');
      expect(Object.keys(DEPRECATED_NPM_PACKAGES)).not.toContain('glob');
    });
  });
});
