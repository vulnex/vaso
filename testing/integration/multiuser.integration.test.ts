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
    // The config's mode is reported once per installation — by the agent's own
    // check when it covers the file, else by CFG-003 (generic duplicates are
    // dropped) — so look for whichever result carries it.
    const permFinding = (dir: string) => {
      const file = `${dir}/config.json`;
      return result.agents.find(a => a.installation.installDir === dir)!.results
        .filter(r => !r.passed)
        .flatMap(r => (r.evidence ?? []).filter(e => e.file === file && /permissions?[:\s]+0?[0-7]{3}|readable/i.test(`${e.snippet ?? ''} ${e.detail ?? ''}`)).map(e => ({ r, e })))[0];
    };
    const bob = permFinding('/home/bob/.nanobot');
    expect(bob).toBeDefined();
    expect(bob.e.mitigated).toBeFalsy();
    expect(bob.r.severity).not.toBe('info');
    const alice = permFinding('/home/alice/.nanobot');
    expect(alice?.e.mitigated).toBe(true);
  });

  it('completes without errored checks', () => {
    const errored = result.agents.flatMap(a => a.results.filter(r => r.errored).map(r => `${a.agent}:${r.id}`));
    expect(errored).toEqual([]);
  });
});
