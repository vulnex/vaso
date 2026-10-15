import { describe, it, expect } from 'vitest';
import type { Evidence } from '../core/types.js';
import { isTestPath, markTestCode } from './test-paths.js';

const ROOT = '/home/test/.claude/skills';

describe('isTestPath', () => {
  it('matches test dirs and test file names below the skills root', () => {
    expect(isTestPath(`${ROOT}/gstack/test/cso-watchdog.test.ts`, [ROOT])).toBe(true);
    expect(isTestPath(`${ROOT}/gstack/design/test/x.ts`, [ROOT])).toBe(true);
    expect(isTestPath(`${ROOT}/pp/tests/helper.py`, [ROOT])).toBe(true);
    expect(isTestPath(`${ROOT}/x/src/__tests__/a.js`, [ROOT])).toBe(true);
    expect(isTestPath(`${ROOT}/x/test/fixtures/app/main.tsx`, [ROOT])).toBe(true);
    expect(isTestPath(`${ROOT}/x/lib/parse.spec.mjs`, [ROOT])).toBe(true);
    expect(isTestPath(`${ROOT}/x/scripts/test_recalc.py`, [ROOT])).toBe(true);
  });

  it('ignores ancestor segments (a user named "test") and ordinary code', () => {
    expect(isTestPath(`${ROOT}/gstack/bin/install.sh`, [ROOT])).toBe(false);
    expect(isTestPath(`${ROOT}/x/testing-utils.js`, [ROOT])).toBe(false);
    expect(isTestPath(`${ROOT}/x/contest/entry.js`, [ROOT])).toBe(false);
  });

  it('does not count the skill directory itself (a skill named "test" or "spec")', () => {
    expect(isTestPath(`${ROOT}/test/index.js`, [ROOT])).toBe(false);
    expect(isTestPath(`${ROOT}/spec/lib/run.js`, [ROOT])).toBe(false);
    expect(isTestPath(`${ROOT}/spec/test/run.js`, [ROOT])).toBe(true);
  });

  it('treats a package root as one unit when asked (resolved MCP packages)', () => {
    expect(isTestPath('/cache/pkg/test/a.js', ['/cache/pkg'], { rootIsUnit: true })).toBe(true);
    expect(isTestPath('/cache/pkg/dist/a.js', ['/cache/pkg'], { rootIsUnit: true })).toBe(false);
  });

  it('never treats files outside every skills root as test code', () => {
    expect(isTestPath('/srv/tests/evil.js', [ROOT])).toBe(false);
    expect(isTestPath(`${ROOT}-other/test/a.js`, [ROOT])).toBe(false);
  });
});

describe('markTestCode', () => {
  it('marks only test-code evidence and annotates it', async () => {
    const evidence: Evidence[] = [
      { file: `${ROOT}/gstack/test/rs.test.ts`, detail: 'Socket-based reverse shell' },
      { file: `${ROOT}/gstack/bin/run.js`, detail: 'spawnSync() call detected' },
    ];
    await markTestCode(evidence, { skillsDir: ROOT });
    expect(evidence[0]).toMatchObject({ mitigated: true });
    expect(evidence[0].detail).toContain('test/fixture code');
    expect(evidence[1].mitigated).toBeUndefined();
  });

  it('marks CI configuration and scripts (.github/, .gitlab/, …) as not loaded', async () => {
    const evidence: Evidence[] = [
      { file: `${ROOT}/gstack/.github/scripts/qualify-dia-macos.ts`, detail: 'macOS Keychain access' },
      { file: `${ROOT}/gstack/.gitlab/ci.yml`, detail: 'Curl-pipe-shell execution' },
      { file: `${ROOT}/gstack/github/notes.ts`, detail: 'spawn() call detected' },
    ];
    await markTestCode(evidence, { skillsDir: ROOT });
    expect(evidence[0].detail).toBe('macOS Keychain access — in CI configuration, not loaded by the agent');
    expect(evidence[1].mitigated).toBe(true);
    expect(evidence[2].mitigated).toBeUndefined();
  });

  it('considers every skills dir and does nothing without one', async () => {
    const extra = '/opt/agent/skills';
    const evidence: Evidence[] = [{ file: `${extra}/s/tests/x.py` }];
    await markTestCode(evidence, {});
    expect(evidence[0].mitigated).toBeUndefined();
    await markTestCode(evidence, { skillsDir: ROOT, skillsDirs: [extra] });
    expect(evidence[0].mitigated).toBe(true);
  });

  it('keeps test-dir code the skill itself tells the agent to run', async () => {
    const fs = { readFile: async (p: string) => (p === `${ROOT}/s/SKILL.md` ? 'Run `node test/run.js` first' : Promise.reject(new Error('ENOENT'))) };
    const evidence: Evidence[] = [{ file: `${ROOT}/s/test/run.js` }, { file: `${ROOT}/s/test/other.js` }];
    await markTestCode(evidence, { skillsDir: ROOT }, fs as never);
    expect(evidence[0].mitigated).toBeUndefined();
    expect(evidence[1].mitigated).toBe(true);
  });
});
