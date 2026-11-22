import { describe, it, expect } from 'vitest';
import { buildBroadPaths, isBroadPath } from './broad-paths.js';

const HOME = '/Users/alice';
const broad = buildBroadPaths(HOME);

describe('isBroadPath', () => {
  it('matches the catalogue exactly, with ~ and trailing slashes', () => {
    expect(isBroadPath('/', broad, HOME)?.reason).toBe('covers the entire filesystem');
    expect(isBroadPath('~', broad, HOME)?.reason).toBe('covers the entire home directory');
    expect(isBroadPath('/Users/alice/', broad, HOME)?.reason).toBe('covers the entire home directory');
    expect(isBroadPath('/tmp', broad, HOME)).toBeDefined();
  });

  it('treats a directory above the home as broad', () => {
    expect(isBroadPath('/Users', broad, HOME)).toEqual({ path: '/Users', reason: 'contains the home directory and every other user\'s' });
    expect(isBroadPath('~/..', broad, HOME)?.path).toBe('/Users');
    expect(isBroadPath('/home', buildBroadPaths('/home/alice'), '/home/alice')?.path).toBe('/home');
  });

  it('does not flag paths inside the home or beside it', () => {
    expect(isBroadPath('/Users/alice/work', broad, HOME)).toBeUndefined();
    expect(isBroadPath('/Users/al', broad, HOME)).toBeUndefined();
    expect(isBroadPath('/opt', broad, HOME)).toBeUndefined();
  });

  it('only when the caller judges the home itself broad', () => {
    expect(isBroadPath('/Users', broad.filter(b => b.path !== HOME), HOME)).toBeUndefined();
  });
});
