import { describe, it, expect } from 'vitest';
import { buildBroadPaths, isBroadPath } from './broad-paths.js';

describe('isBroadPath with ancestors', () => {
  const home = '/Users/alice';
  const broad = buildBroadPaths(home);

  it('matches the catalogue exactly; without ancestors only a folder above the home widens', () => {
    expect(isBroadPath('/', broad, home)?.reason).toMatch(/entire filesystem/);
    expect(isBroadPath('~/', broad, home)?.reason).toMatch(/home directory/);
    expect(isBroadPath('/private/tmp', broad, home)?.reason).toMatch(/all local users/);
    expect(isBroadPath('/private', broad, home)).toBeUndefined();
    expect(isBroadPath('/Users/alice/code/app', broad, home)).toBeUndefined();
  });

  it('with ancestors, flags a folder above a broad path', () => {
    const opts = { ancestors: true };
    expect(isBroadPath('/Users', broad, home, opts)?.reason).toMatch(/every home directory under it, \/Users\/alice included/);
    expect(isBroadPath('/Users/', broad, home, opts)?.path).toBe('/Users');
    expect(isBroadPath('/private', broad, home, opts)?.reason).toMatch(/contains \/private\/tmp/);
    expect(isBroadPath('/var', broad, home, opts)?.reason).toMatch(/contains \/var\/tmp/);
    // a folder below the home, or beside it, is not
    expect(isBroadPath('/Users/alice/code', broad, home, opts)).toBeUndefined();
    expect(isBroadPath('/Users/al', broad, home, opts)).toBeUndefined();
    expect(isBroadPath('/opt/work', broad, home, opts)).toBeUndefined();
  });
});

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
