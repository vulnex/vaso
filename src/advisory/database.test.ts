import { describe, it, expect, beforeEach } from 'vitest';
import {
  buildBundledAdvisoryDatabase,
  getAdvisoryDatabase,
  reloadAdvisoryDatabase,
} from './database.js';
import { satisfies } from '../core/semver.js';

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
    const db = buildBundledAdvisoryDatabase();
    for (const adv of db.advisories) {
      if (/^(CVE|GHSA)-/.test(adv.id)) expect(adv.reference, adv.id).toMatch(/^https:\/\//);
      expect(adv.reference ?? '').not.toContain('vulnex/vaso-advisories');
      expect(adv.id).not.toMatch(/^CVE-2026-40(0\d\d|100)$/);
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

