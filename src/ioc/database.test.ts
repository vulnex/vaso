import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildBundledDatabase, getIOCDatabase, reloadIOCDatabase } from './database.js';

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
    const hasIP = db.c2Ips.includes('91.92.242.30');
    console.log(`[IOC DB] ClawHavoc C2 IP 91.92.242.30 → present: ${hasIP}`);
    expect(db.c2Ips).toContain('91.92.242.30');
  });

  it('contains known malicious domains', () => {
    const db = getIOCDatabase();
    const hasDomain = db.maliciousDomains.includes('santaclaude.app');
    console.log(`[IOC DB] malicious domain santaclaude.app → present: ${hasDomain}`);
    expect(db.maliciousDomains).toContain('santaclaude.app');
  });

  it('contains malicious publishers', () => {
    const db = getIOCDatabase();
    const hasPublisher = db.maliciousPublishers.includes('hightower6eu');
    console.log(`[IOC DB] malicious publisher "clawhavoc" → present: ${hasPublisher}`);
    expect(db.maliciousPublishers).toContain('hightower6eu');
  });
});

// v0.1.0 shipped textbook test values as IOCs (empty-file hash, "hello world",
// RFC 5737 documentation IPs, scanme.nmap.org), flagging benign content as
// critical. Neither the bundled DB nor the published feed may contain them.
describe('IOC data integrity — no placeholder / test-vector indicators', () => {
  const TEST_INPUTS = ['', 'hello world', 'hello world\n', 'test', 'abc', 'foo', 'password',
    'The quick brown fox jumps over the lazy dog'];
  const TEST_VECTOR_HASHES = new Set(TEST_INPUTS.flatMap(v => [
    createHash('sha256').update(v).digest('hex'),
    createHash('sha3-256').update(v).digest('hex'),
  ]));
  // RFC 5737 documentation, RFC 1918 private, loopback, link-local, Nmap's scan-me host
  const NON_C2_IP = /^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|0\.)|^45\.33\.32\.156$/;

  const published = JSON.parse(readFileSync(join(__dirname, '../../feeds/feed.json'), 'utf8')) as {
    data: { fileHashes?: string[]; c2Ips?: string[] };
  };
  const sources = [
    { name: 'bundled', hashes: buildBundledDatabase().fileHashes, ips: buildBundledDatabase().c2Ips },
    { name: 'feeds/feed.json', hashes: published.data.fileHashes ?? [], ips: published.data.c2Ips ?? [] },
  ];

  for (const src of sources) {
    it(`${src.name}: no file hash is a well-known test vector`, () => {
      expect(src.hashes.filter(h => TEST_VECTOR_HASHES.has(h.toLowerCase()))).toEqual([]);
    });

    it(`${src.name}: no C2 IP is a documentation, private, or scan-test address`, () => {
      expect(src.ips.filter(ip => NON_C2_IP.test(ip))).toEqual([]);
    });
  }
});

