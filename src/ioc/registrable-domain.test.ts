import { describe, it, expect } from 'vitest';
import { registrableDomain, registrableLabel } from './registrable-domain.js';

describe('registrableDomain', () => {
  it('drops subdomains down to the registered name', () => {
    expect(registrableDomain('agenthub.contetial.com')).toBe('contetial.com');
    expect(registrableDomain('newsradar.dreamdt.cn')).toBe('dreamdt.cn');
    expect(registrableDomain('relay.lmfao.su')).toBe('lmfao.su');
    expect(registrableDomain('giftshop.club')).toBe('giftshop.club');
    expect(registrableDomain('Too.Clawddddd.COM.')).toBe('clawddddd.com');
  });

  it('knows multi-label suffixes: country second levels and hosting platforms', () => {
    expect(registrableDomain('www.example.co.uk')).toBe('example.co.uk');
    expect(registrableDomain('a.b.shop.com.cn')).toBe('shop.com.cn');
    expect(registrableLabel('openclawcli.vercel.app')).toBe('openclawcli');
    expect(registrableLabel('remote-claude-relay.fly.dev')).toBe('remote-claude-relay');
    expect(registrableLabel('x.productivity-suite-mcp.onrender.com')).toBe('productivity-suite-mcp');
  });

  it('has none for a bare suffix or an address', () => {
    expect(registrableDomain('com')).toBeUndefined();
    expect(registrableDomain('vercel.app')).toBeUndefined();
    expect(registrableDomain('co.uk')).toBeUndefined();
    expect(registrableDomain('91.92.242.30')).toBeUndefined();
    expect(registrableDomain('::1')).toBeUndefined();
  });
});
