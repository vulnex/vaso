import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtemp, readFile, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, normalize, resolve } from 'node:path';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { expandManifestGlob, splitGlob } from '../core/probe-coverage.js';
import { envTreeRefusal } from '../core/skill-root-scope.js';
import { screenDefaultSkillRoots } from './default-skill-roots.js';
import { registerAllAdapters } from './index.js';
import { adapterRegistry } from './registry.js';

/** A local provider whose home is `home` and whose environment is `env`. */
function withEnv(home: string, env: Record<string, string>): LocalFSProvider {
  return Object.assign(Object.create(new LocalFSProvider()) as LocalFSProvider, {
    homedir: () => home,
    getEnv: (k: string) => env[k],
  });
}

describe('manifest globs an environment variable roots (probe/env_globs.go parity)', () => {
  let home: string;

  beforeAll(async () => {
    if (adapterRegistry.getAdapters().length === 0) registerAllAdapters();
    home = await realpath(await mkdtemp(join(tmpdir(), 'vaso-envglob-')));
  });

  it('refuses the bases of probe/testdata/env-glob-cases.json as the probe does', async () => {
    const cases = JSON.parse(await readFile(resolve(import.meta.dirname, '../../probe/testdata/env-glob-cases.json'), 'utf-8')) as
      Array<{ value: string; glob: string; refused: boolean }>;
    expect(cases.length).toBeGreaterThanOrEqual(10);
    for (const c of cases) {
      const value = normalize(c.value.replaceAll('$HOME', home)).replace(/(.)\/$/, '$1');
      const name = /^\$\{(\w+)\}/.exec(c.glob)![1];
      const fs = withEnv(home, { [name]: value });
      const exp = expandManifestGlob(fs, c.glob, home)!;
      const label = await envTreeRefusal(fs, splitGlob(exp.prefix + exp.tail).base, [home]);
      expect(label !== undefined, `${name}=${c.value} ${c.glob} → ${label}`).toBe(c.refused);
    }
  });

  // dt24 g1-R1: OPENCLAW_STATE_DIR=/var/lib/openclaw (a systemd
  // StateDirectory) — the probe skipped its skills, local scans read them
  it('keeps an agent skills tree its variable puts under /var/lib', async () => {
    const fs = withEnv(home, { OPENCLAW_STATE_DIR: '/var/lib/openclaw' });
    const dir = '/var/lib/openclaw/skills';
    const [inst] = await screenDefaultSkillRoots([{
      agent: 'openclaw', installDir: '/var/lib/openclaw', configFiles: [], skillsDir: dir, skillsDirs: [dir],
    }], fs);
    expect(inst.skillsDirs).toEqual([dir]);
    expect(inst.unscannedSkillsDirs ?? []).toEqual([]);
  });

  it('reports a tree whose variable points into another user\'s home as not scanned', async () => {
    const other = '/home/someone-else/.openclaw';
    const fs = withEnv(home, { OPENCLAW_STATE_DIR: other });
    const dir = join(other, 'skills');
    const [inst] = await screenDefaultSkillRoots([{
      agent: 'openclaw', installDir: other, configFiles: [], skillsDir: dir, skillsDirs: [dir],
    }], fs);
    expect(inst.skillsDirs).toEqual([]);
    expect(inst.unscannedSkillsDirs).toEqual([
      { path: dir, reason: 'outside', refusedAs: "another user's home (/home/someone-else)", agentDefault: true },
    ]);
  });

  it('reports PicoClaw workspaces under a PICOCLAW_HOME at the filesystem root as not scanned', async () => {
    const fs = withEnv(home, { PICOCLAW_HOME: '/' });
    const dir = '/workspace-a/skills';
    const [inst] = await screenDefaultSkillRoots([{
      agent: 'picoclaw', installDir: '/', configFiles: [], skillsDir: dir, skillsDirs: [dir],
    }], fs);
    expect(inst.unscannedSkillsDirs).toEqual([
      { path: dir, reason: 'outside', refusedAs: 'the filesystem root', agentDefault: true },
    ]);
  });

  it('keeps a tree a home glob also walks', async () => {
    const fs = withEnv(home, { CLAUDE_CONFIG_DIR: join(home, '.claude') });
    const dir = join(home, '.claude', 'skills');
    const [inst] = await screenDefaultSkillRoots([{
      agent: 'claude-code', installDir: dirname(dir), configFiles: [], skillsDir: dir, skillsDirs: [dir],
    }], fs);
    expect(inst.unscannedSkillsDirs ?? []).toEqual([]);
  });
});
