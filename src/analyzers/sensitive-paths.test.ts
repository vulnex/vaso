import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { SENSITIVE_SINKS, classifySensitivePath } from './sensitive-paths.js';

describe('SENSITIVE_SINKS', () => {
  it('is the list the probe enforces (probe/sensitive_sinks.go), pattern for pattern', () => {
    // The probe never ships content behind a skill link into one of these
    // locations, and the local skill walk never follows one: the two lists
    // must not drift (TestSensitiveSinksMatchTS checks the other direction).
    const go = readFileSync(join(__dirname, '..', '..', 'probe', 'sensitive_sinks.go'), 'utf-8');
    const block = /var sensitiveSinkPatterns = \[\]string\{([\s\S]*?)\n\}/.exec(go);
    expect(block).not.toBeNull();
    const probe = [...block![1].matchAll(/`([^`]*)`/g)].map(m => m[1]);
    expect(probe).toEqual(SENSITIVE_SINKS.map(s => s.re.source));
    // The probe compiles each one with (?i)
    expect(SENSITIVE_SINKS.every(s => s.re.flags === 'i')).toBe(true);
  });

  it('classifies credential stores and leaves ordinary paths alone', () => {
    expect(classifySensitivePath('/home/u/.ssh/id_ed25519')).toHaveLength(1);
    expect(classifySensitivePath('/home/u/.aws/credentials')).toHaveLength(1);
    expect(classifySensitivePath('/home/u/.claude/skills/sshlink')).toEqual([]);
  });
});
