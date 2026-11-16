import { describe, it, expect } from 'vitest';
import { leftAsNoted } from './engine.js';
import type { CheckResult, FixResult } from '../core/types.js';

const finding = (id: string, message: string, extra: Partial<CheckResult> = {}): CheckResult => ({
  id, name: id, category: 'policy', severity: 'warning', passed: false, message, fixable: true, ...extra,
});

describe('leftAsNoted', () => {
  const refusedEnv: FixResult = { checkId: 'POL-003', applied: false, message: 'not changed: /h/.hermes/.env is a symlink', refused: ['/h/.hermes/.env'] };

  it('a fix with only files the scan named "not changed by vaso fix" left is not a failure', () => {
    const r = leftAsNoted(refusedEnv, finding('POL-003', 'open; not changed by vaso fix: /h/.hermes/.env is a symlink'), []);
    expect(r).toMatchObject({ applied: false, leftAsNoted: true });
    expect(r.message).toMatch(/^nothing left that vaso fix may change — /);
  });

  it('a folded finding: the note is in the message of the finding it was folded into', () => {
    const folded = finding('POL-003', 'Reported by HM-003', { passed: true, foldedInto: 'HM-003' });
    const owner = finding('HM-003', 'Hermes credentials open; not changed by vaso fix: /h/.hermes/.env is a symlink');
    expect(leftAsNoted(refusedEnv, folded, [owner]).leftAsNoted).toBe(true);
  });

  it('a folded finding\'s own note lives in its fix description (its passing message has none)', () => {
    const folded = finding('POL-003', 'Reported by HM-003', {
      passed: true, foldedInto: 'HM-003', fixDescription: 'chmod 600; not changed by vaso fix: /h/.hermes/.env is a symlink',
    });
    expect(leftAsNoted(refusedEnv, folded, [finding('HM-003', 'Found 3 Hermes credential file(s)')]).leftAsNoted).toBe(true);
  });

  it('counts the paths markRefusedFix summarized as "N more"', () => {
    const r = leftAsNoted({ ...refusedEnv, refused: ['/h/z'] }, finding('POL-003', 'open; not changed by vaso fix: /h/a is a symlink; /h/b is a symlink; /h/c is a symlink; 1 more'), []);
    expect(r.leftAsNoted).toBe(true);
  });

  it('a refusal the scan did not name, an error, or an applied fix stays as it is', () => {
    expect(leftAsNoted(refusedEnv, finding('POL-003', 'open'), []).leftAsNoted).toBeUndefined();
    expect(leftAsNoted(refusedEnv, finding('POL-003', 'open; not changed by vaso fix: /h/other is a symlink'), []).leftAsNoted).toBeUndefined();
    const failed: FixResult = { checkId: 'POL-003', applied: false, message: 'EPERM' };
    expect(leftAsNoted(failed, finding('POL-003', 'open; not changed by vaso fix: /h/.hermes/.env is a symlink'), [])).toBe(failed);
    const applied: FixResult = { ...refusedEnv, applied: true };
    expect(leftAsNoted(applied, finding('POL-003', 'x'), [])).toBe(applied);
  });
});
