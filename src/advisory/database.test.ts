import { describe, it, expect, beforeEach } from 'vitest';
import {
  buildBundledAdvisoryDatabase,
  getAdvisoryDatabase,
  reloadAdvisoryDatabase,
} from './database.js';

describe('AdvisoryDatabase', () => {
  beforeEach(() => {
    reloadAdvisoryDatabase();
  });

  it('builds bundled database with advisory entries', () => {
    const db = buildBundledAdvisoryDatabase();
    expect(db.advisories.length).toBeGreaterThan(10);
  });

  it('contains advisories for all agent types', () => {
    const db = buildBundledAdvisoryDatabase();
    const agents = new Set(db.advisories.map(a => a.agent));
    expect(agents.has('openclaw')).toBe(true);
    expect(agents.has('nanoclaw')).toBe(true);
    expect(agents.has('picoclaw')).toBe(true);
    expect(agents.has('ironclaw')).toBe(true);
    expect(agents.has('nanobot')).toBe(true);
    expect(agents.has('zeroclaw')).toBe(true);
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

  it('contains EOL notices', () => {
    const db = buildBundledAdvisoryDatabase();
    const eol = db.advisories.filter(a => a.eolNotice);
    expect(eol.length).toBeGreaterThan(0);
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
