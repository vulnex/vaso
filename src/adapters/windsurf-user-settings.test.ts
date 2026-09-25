import { describe, it, expect } from 'vitest';
import { decodeWindsurfUserSettings, toWindsurfSettingsData } from './windsurf-user-settings.js';

// Minimal protobuf encoder for fixtures
function varint(n: number): number[] {
  const out: number[] = [];
  while (n >= 0x80) { out.push((n % 0x80) | 0x80); n = Math.floor(n / 0x80); }
  out.push(n);
  return out;
}
const enumField = (field: number, value: number) => [...varint(field * 8), ...varint(value)];
function bytesField(field: number, data: Uint8Array | string): number[] {
  const b = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return [...varint(field * 8 + 2), ...varint(b.length), ...b];
}

describe('decodeWindsurfUserSettings', () => {
  it('extracts the command/web policies and allow/deny lists, skipping the model catalogue', () => {
    const catalogue = new Uint8Array(5000).fill(7);
    const buf = new Uint8Array([
      ...enumField(1, 1),
      ...bytesField(52, catalogue),
      ...enumField(27, 3), // EAGER == Turbo
      ...bytesField(85, 'git status'),
      ...bytesField(14, 'bash'),
      ...bytesField(86, 'rm'),
      ...enumField(90, 3),
    ]);
    const s = decodeWindsurfUserSettings(buf)!;
    expect(s.autoExecutionPolicy).toBe('turbo');
    expect(s.webRequestsAutoExecutionPolicy).toBe('turbo');
    expect(s.allowedCommands).toEqual(['git status', 'bash']);
    expect(s.deniedCommands).toEqual(['rm']);
    expect(toWindsurfSettingsData(s)).toEqual({
      windsurf: {
        autoExecutionPolicy: 'turbo',
        webRequestsAutoExecutionPolicy: 'turbo',
        cascadeCommandsAllowList: ['git status', 'bash'],
        cascadeCommandsDenyList: ['rm'],
      },
    });
  });

  it('maps the remaining command policy values', () => {
    expect(decodeWindsurfUserSettings(new Uint8Array(enumField(27, 1)))?.autoExecutionPolicy).toBe('off');
    expect(decodeWindsurfUserSettings(new Uint8Array(enumField(27, 2)))?.autoExecutionPolicy).toBe('auto');
    expect(decodeWindsurfUserSettings(new Uint8Array(enumField(27, 4)))?.autoExecutionPolicy).toBe('disabled');
  });

  it('leaves the policy unset when field 27 is absent (product default)', () => {
    const s = decodeWindsurfUserSettings(new Uint8Array([...enumField(1, 1), ...bytesField(52, 'x')]))!;
    expect(s.autoExecutionPolicy).toBeUndefined();
    expect(toWindsurfSettingsData(s)).toEqual({ windsurf: {} });
  });

  it('rejects malformed input instead of guessing', () => {
    expect(decodeWindsurfUserSettings(new Uint8Array([0x0a, 0x10, 0x01]))).toBeUndefined(); // length overruns
    expect(decodeWindsurfUserSettings(new TextEncoder().encode('{"not":"protobuf"}'))).toBeUndefined();
  });
});
