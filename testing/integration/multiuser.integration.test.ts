import { describe, it, expect, beforeAll } from 'vitest';
import type { ScanResult } from '../../src/core/types.js';
import { runVasoScan } from './helpers.js';

describe('Multi-user host (root, --all-users)', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/multiuser.Dockerfile',
      cliArgs: ['--all-users'],
    });
  });

  const installs = () => result.agents.map(a => `${a.agent}:${a.installation.installDir}`).sort();

  it('attributes every framework install to its user, once', () => {
    const fw = installs().filter(i => /^(picoclaw|nanobot|zeroclaw):/.test(i));
    expect(fw).toEqual([
      'nanobot:/home/alice/.nanobot',
      'nanobot:/home/bob/.nanobot',
      'picoclaw:/home/alice/.picoclaw',
      'zeroclaw:/home/bob/.zeroclaw',
    ]);
    expect(new Set(installs()).size).toBe(installs().length);
  });

  it('judges permissions per user home (private home mitigates, open home does not)', () => {
    const cfg003 = (dir: string) => result.agents
      .find(a => a.installation.installDir === dir)!.results.find(r => r.id === 'CFG-003')!;
    expect(cfg003('/home/bob/.nanobot').passed).toBe(false);
    expect(cfg003('/home/bob/.nanobot').severity).not.toBe('info');
    expect(cfg003('/home/alice/.nanobot').severity).toBe('info');
  });

  it('completes without errored checks', () => {
    const errored = result.agents.flatMap(a => a.results.filter(r => r.errored).map(r => `${a.agent}:${r.id}`));
    expect(errored).toEqual([]);
  });
});
