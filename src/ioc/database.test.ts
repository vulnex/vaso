import { describe, it, expect } from 'vitest';
import { getIOCDatabase, reloadIOCDatabase } from './database.js';

describe('IOC Database', () => {
  it('loads database with expected data', () => {
    const db = getIOCDatabase();
    console.log(`[IOC DB] loaded → c2Ips: ${db.c2Ips.length}, domains: ${db.maliciousDomains.length}, hashes: ${db.fileHashes.length}, publishers: ${db.maliciousPublishers.length}, patterns: ${db.maliciousSkillPatterns.length}, trusted: ${db.trustedSkillNames.length}`);
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
    const sameData = JSON.stringify(db2.c2Ips) === JSON.stringify(db1.c2Ips);
    const differentRef = db2 !== db1;
    console.log(`[IOC DB] reload → same data: ${sameData}, different object ref: ${differentRef}`);
    expect(db2.c2Ips).toEqual(db1.c2Ips);
    expect(db2).not.toBe(db1);
  });

  it('contains known ClawHavoc C2 IP', () => {
    const db = getIOCDatabase();
    const hasIP = db.c2Ips.includes('185.199.228.220');
    console.log(`[IOC DB] ClawHavoc C2 IP 185.199.228.220 → present: ${hasIP}`);
    expect(db.c2Ips).toContain('185.199.228.220');
  });

  it('contains known malicious domains', () => {
    const db = getIOCDatabase();
    const hasDomain = db.maliciousDomains.includes('clawhavoc.io');
    console.log(`[IOC DB] malicious domain clawhavoc.io → present: ${hasDomain}`);
    expect(db.maliciousDomains).toContain('clawhavoc.io');
  });

  it('contains malicious publishers', () => {
    const db = getIOCDatabase();
    const hasPublisher = db.maliciousPublishers.includes('clawhavoc');
    console.log(`[IOC DB] malicious publisher "clawhavoc" → present: ${hasPublisher}`);
    expect(db.maliciousPublishers).toContain('clawhavoc');
  });
});
