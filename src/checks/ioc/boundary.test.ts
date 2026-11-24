import { describe, expect, it } from 'vitest';
import { domainBoundaryRegex, ipBoundaryRegex } from './boundary.js';

/** dt25 g5-F1: a trailing dot that starts no label is a boundary, not a miss. */
describe('IOC boundaries', () => {
  const dom = domainBoundaryRegex('giftshop.club');
  const ip = ipBoundaryRegex('91.92.242.30');

  it.each([
    'giftshop.club',
    'Send it to giftshop.club.',
    'see giftshop.club. Then',
    'https://giftshop.club./u',
    'https://bad.giftshop.club./u',
    'GIFTSHOP.CLUB.',
    '"giftshop.club."',
    'giftshop.club..',
  ])('domain matches %j', (s) => { expect(dom.test(s)).toBe(true); });

  it.each([
    'giftshop.club.example',
    'giftshop.club.cn/x',
    'giftshop.clubhouse.org',
    'notgiftshop.club',
    'giftshop.club-x.org',
    'giftshop.club._srv',
  ])('domain does not match %j', (s) => { expect(dom.test(s)).toBe(false); });

  it.each([
    '91.92.242.30',
    'C2 at 91.92.242.30.',
    'http://91.92.242.30./x',
    '91.92.242.30:8080',
  ])('IP matches %j', (s) => { expect(ip.test(s)).toBe(true); });

  it.each([
    '91.92.242.300',
    '91.92.242.30.5',
    '191.92.242.30',
    '1.91.92.242.30',
    '91.92.242.30.example',
  ])('IP does not match %j', (s) => { expect(ip.test(s)).toBe(false); });
});
