import { describe, it, expect } from 'vitest';
import { hermesServerEnabled, hermesServerMap, isDisabledServerConfig } from './disabled.js';

describe('Hermes enabled/disabled, as mcp_server_enabled reads them', () => {
  it.each([
    [{}, true],
    [{ enabled: null }, true],
    [{ enabled: true }, true],
    [{ enabled: false }, false],
    [{ enabled: 0 }, false], // PyYAML int 0
    [{ enabled: 1 }, true],
    [{ enabled: 'no' }, false], // `enabled: no` (1.2 string) and `enabled: "no"` alike
    [{ enabled: ' OFF ' }, false],
    [{ enabled: 'nO' }, false],
    [{ enabled: '0' }, false],
    [{ enabled: 'yes' }, true],
    [{ enabled: 'maybe' }, true], // unparseable → default on
    [{ disabled: true }, false],
    [{ enabled: true, disabled: 'yes' }, false], // legacy disabled wins
    [{ disabled: 'no' }, true],
  ])('%j → %s', (entry, on) => {
    expect(hermesServerEnabled(entry)).toBe(on);
    expect(isDisabledServerConfig(entry, { yaml11: true })).toBe(!on);
  });

  it('marks the servers Hermes skips, and leaves other agents to their own rule', () => {
    expect(hermesServerMap({ a: { enabled: 0 }, b: { enabled: 'on' } })).toEqual({ a: { enabled: false }, b: { enabled: 'on' } });
    expect(isDisabledServerConfig({ enabled: 0 })).toBe(false);
    expect(isDisabledServerConfig({ disabled: true })).toBe(true);
  });
});
