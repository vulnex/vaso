import { describe, it, expect } from 'vitest';
import { getIOCDatabase, reloadIOCDatabase } from './database.js';

describe('IOC Database', () => {
  it('loads database with expected data', () => {
    const db = getIOCDatabase();
    expect(db.c2Ips.length).toBeGreaterThan(0);
    expect(db.maliciousDomains.length).toBeGreaterThan(0);
    expect(db.fileHashes.length).toBeGreaterThan(0);
    expect(db.maliciousPublishers.length).toBeGreaterThan(0);
    expect(db.maliciousSkillPatterns.length).toBeGreaterThan(0);
    expect(db.trustedSkillNames.length).toBeGreaterThan(0);
  });

  it('reloads database', () => {
    const db1 = getIOCDatabase();
    reloadIOCDatabase();
    const db2 = getIOCDatabase();
    expect(db2.c2Ips).toEqual(db1.c2Ips);
    expect(db2).not.toBe(db1); // Different object
  });

  it('contains known ClawHavoc C2 IP', () => {
    const db = getIOCDatabase();
    expect(db.c2Ips).toContain('185.199.228.220');
  });

  it('contains known malicious domains', () => {
    const db = getIOCDatabase();
    expect(db.maliciousDomains).toContain('clawhavoc.io');
  });

  it('contains malicious publishers', () => {
    const db = getIOCDatabase();
    expect(db.maliciousPublishers).toContain('clawhavoc');
  });
});
