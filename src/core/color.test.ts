import { describe, it, expect } from 'vitest';
import { colorDisabled } from './color.js';

describe('colorDisabled', () => {
  it('honours --no-color even when FORCE_COLOR is set, and NO_COLOR', () => {
    expect(colorDisabled(['scan', '--no-color'], { FORCE_COLOR: '1' })).toBe(true);
    expect(colorDisabled(['scan'], { NO_COLOR: '1' })).toBe(true);
    expect(colorDisabled(['scan'], { FORCE_COLOR: '1' })).toBe(false);
    expect(colorDisabled(['scan', '--', '--no-color'], {})).toBe(false);
  });
});
