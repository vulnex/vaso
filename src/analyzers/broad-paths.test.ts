import { describe, it, expect } from 'vitest';
import { buildBroadPaths, isBroadPath } from './broad-paths.js';

describe('isBroadPath', () => {
  const home = '/Users/alice';
  const broad = buildBroadPaths(home);

  it('matches the catalogue exactly by default', () => {
    expect(isBroadPath('/', broad, home)?.reason).toMatch(/entire filesystem/);
    expect(isBroadPath('~/', broad, home)?.reason).toMatch(/home directory/);
    expect(isBroadPath('/private/tmp', broad, home)?.reason).toMatch(/all local users/);
    expect(isBroadPath('/Users', broad, home)).toBeUndefined();
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
