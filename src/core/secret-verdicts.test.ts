import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { isPlaceholderSecret, isSecretReference } from './patterns.js';
import { WEAK_PATTERNS } from '../checks/config/cfg-009-default-credentials.js';
import { isKnownSecretValue } from '../analyzers/secret-values.js';

/**
 * The probe disguises secrets in collected config files (probe/secret_scrub.go)
 * and keeps placeholders, references and weak defaults as they are. It
 * reaches those judgements with Go ports of the functions below; both sides
 * are held to the same corpus (TestSecretVerdictsMatchCLI on the Go side).
 */
describe('probe secret-verdict corpus', () => {
  const cases = JSON.parse(readFileSync(join(__dirname, '..', '..', 'probe', 'testdata', 'secret-verdicts.json'), 'utf-8')) as
    Array<{ value: string; placeholder: boolean; weak: boolean; reference: boolean; token?: boolean }>;

  it.each(cases)('$value', (c) => {
    expect({
      placeholder: isPlaceholderSecret(c.value),
      weak: WEAK_PATTERNS.some(p => p.test(c.value)),
      reference: isSecretReference(c.value),
    }).toEqual({ placeholder: c.placeholder, weak: c.weak, reference: c.reference });
    // a known token format (the probe keeps every format a value matches)
    if (c.token !== undefined) expect(isKnownSecretValue(c.value)).toBe(c.token);
  });
});
