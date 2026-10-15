import { describe, it, expect } from 'vitest';
import type { CheckResult, Evidence } from './types.js';
import { dedupePermissionFindings } from './duplicate-findings.js';

const r = (id: string, evidence: Evidence[], extra: Partial<CheckResult> = {}): CheckResult => ({
  id, name: id, category: id.startsWith('CFG') ? 'config' : id.startsWith('POL') ? 'policy' : 'coding-agent',
  severity: 'warning', passed: evidence.length === 0, message: `${id} failed`, evidence: evidence.length ? evidence : undefined, ...extra,
});
const perm = (file: string) => ({ file, detail: 'Permissions: 664 (should be 600 or tighter)' });

describe('dedupePermissionFindings', () => {
  it('POL-003 yields to CFG-003 for the same config file', () => {
    const out = dedupePermissionFindings([r('CFG-003', [perm('/h/.claude/settings.json')]), r('POL-003', [perm('/h/.claude/settings.json')])]);
    expect(out.find(x => x.id === 'CFG-003')?.passed).toBe(false);
    const pol = out.find(x => x.id === 'POL-003')!;
    expect(pol.passed).toBe(true);
    expect(pol.message).toBe('Reported by CFG-003');
  });

  it('generic checks yield to the agent check that reports the file mode', () => {
    const out = dedupePermissionFindings([
      r('DEV-002', [{ file: '/h/.local/share/devin/credentials.toml', snippet: 'mode 0664', detail: 'credentials.toml is readable by group/other' }]),
      r('POL-003', [perm('/h/.local/share/devin/credentials.toml'), perm('/h/.local/share/devin/other.json')]),
    ]);
    const pol = out.find(x => x.id === 'POL-003')!;
    expect(pol.passed).toBe(false);
    expect(pol.evidence?.map(e => e.file)).toEqual(['/h/.local/share/devin/other.json']);
    expect(pol.message).toContain('other files reported by DEV-002');
  });

  it('keeps a folded CFG-003 fixable (counted once, still fixed by `vaso fix`)', () => {
    const out = dedupePermissionFindings([
      r('LY-006', [{ file: '/h/lyrie/.env', detail: 'Permissions: 644 (should be 600 or tighter)' }]),
      r('CFG-003', [perm('/h/lyrie/.env')], { fixable: true, fixDescription: 'Remove group/other access' }),
    ]);
    expect(out.find(x => x.id === 'CFG-003')).toMatchObject({ passed: true, fixable: true, foldedInto: 'LY-006' });
    expect(out.find(x => x.id === 'LY-006')).toMatchObject({ passed: false });
    expect(out.find(x => x.id === 'LY-006')?.fixable).toBeUndefined();
  });

  it('never drops a permission finding because another check flagged something else in that file', () => {
    const out = dedupePermissionFindings([
      r('QC-001', [{ file: '/h/.qwen/settings.json', detail: 'Plaintext secret in Qwen settings' }]),
      r('CFG-003', [perm('/h/.qwen/settings.json')]),
    ]);
    expect(out.find(x => x.id === 'CFG-003')?.passed).toBe(false);
  });

  it('leaves results untouched when nothing overlaps', () => {
    const input = [r('CFG-003', [perm('/a')]), r('POL-003', [perm('/b')])];
    expect(dedupePermissionFindings(input)).toBe(input);
  });
});
