import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { configHoldsSecret, isSecretLikeValue, unloadedFileExposes } from './secret-values.js';
import { LocalFSProvider } from './local-fs-provider.js';
import { SnapshotFSProvider } from './snapshot-fs-provider.js';

describe('configHoldsSecret', () => {
  it('is false for ordinary settings', () => {
    expect(configHoldsSecret({})).toBe(false);
    expect(configHoldsSecret({ ui: { theme: 'GitHub' }, model: { name: 'gemini-2.5-pro' }, permissions: { allow: ['Bash(npm test)'] } })).toBe(false);
    expect(configHoldsSecret({ env: { OPENAI_API_KEY: '${OPENAI_API_KEY}', TOKEN: 'your-token-here' } })).toBe(false);
  });

  it('finds keys by format or by a secret key name with a random value', () => {
    expect(configHoldsSecret({ env: { ANTHROPIC_API_KEY: 'sk-ant-api03-Ab3dEf6hIj9kLm2nOp5qRs8tUv' } })).toBe(true);
    expect(configHoldsSecret({ mcpServers: { x: { headers: { Authorization: 'Bearer q8Z2vK4mN7pR1sT5wX9yB3cF6hJ0' } } } })).toBe(true);
    expect(isSecretLikeValue('q8Z2vK4mN7pR1sT5wX9yB3cF6hJ0', 'description')).toBe(false);
  });

  it('walks a config nested far deeper than the call stack allows', () => {
    const depth = 200_000;
    const deep = JSON.parse(`{"a":${'['.repeat(depth)}${']'.repeat(depth)}}`) as unknown;
    expect(configHoldsSecret(deep)).toBe(false);
    // a key early in document order is still found
    expect(configHoldsSecret({ env: { ANTHROPIC_API_KEY: 'sk-ant-api03-Ab3dEf6hIj9kLm2nOp5qRs8tUv' }, a: deep })).toBe(true);
  });
});

describe('unloadedFileExposes on a settings file linked into /etc', () => {
  it('is not counted, locally or from a snapshot (neither reads it)', async () => {
    const home = await mkdtemp(join(tmpdir(), 'vaso-sink-settings-'));
    try {
      await mkdir(join(home, '.claude'));
      await symlink('/etc/hosts', join(home, '.claude', 'settings.json'));
      expect(await unloadedFileExposes(new LocalFSProvider(), join(home, '.claude', 'settings.json'))).toBe(false);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
    const snap = new SnapshotFSProvider({
      version: 1, hostname: 'h', platform: 'linux', homedir: '/home/u', timestamp: '2026-11-15T00:00:00Z',
      privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
      files: { '/home/u/.claude/settings.json': { content: '', mode: 0o644, exists: true, contentOmitted: true, omitted: 'sensitive' } },
      directories: {}, commandOutputs: {}, env: {},
    });
    expect(await unloadedFileExposes(snap, '/home/u/.claude/settings.json')).toBe(false);
    // content the probe left out for size is still unknown: counted
    const big = new SnapshotFSProvider({
      version: 1, hostname: 'h', platform: 'linux', homedir: '/home/u', timestamp: '2026-11-15T00:00:00Z',
      privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
      files: { '/home/u/.claude/settings.json': { content: '', mode: 0o644, exists: true, contentOmitted: true, omitted: 'size' } },
      directories: {}, commandOutputs: {}, env: {},
    });
    expect(await unloadedFileExposes(big, '/home/u/.claude/settings.json')).toBe(true);
  });
});
