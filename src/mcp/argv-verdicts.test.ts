import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { findArgSecrets } from './config-secrets.js';
import { maskCredentialsDeep, maskCredentialsInText } from '../reporting/serialize.js';

/**
 * The shared argv corpus (probe/testdata/argv-verdicts.json): the probe's Go
 * test reads the same file, so the scrubber, the report masker and MCP-003
 * agree on which argv values are credentials.
 */
interface ArgvCase { name: string; argv?: string[]; command?: string; secrets: string[]; keep: string[] }
const corpus = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'probe', 'testdata', 'argv-verdicts.json'), 'utf-8')) as { cases: ArgvCase[] };

describe('shared argv rules (probe/testdata/argv-verdicts.json)', () => {
  it('has cases', () => expect(corpus.cases.length).toBeGreaterThan(20));

  for (const c of corpus.cases.filter(x => x.argv)) {
    const [command, ...args] = c.argv!;
    it(`MCP-003 detection: ${c.name}`, () => {
      expect(findArgSecrets(args, command).map(s => s.value).sort()).toEqual([...c.secrets].sort());
    });
    it(`report masker: ${c.name}`, () => {
      const masked = maskCredentialsDeep({ command, args }).args;
      const text = masked.join(' ');
      for (const s of c.secrets) expect(text, s).not.toContain(s);
      for (const k of c.keep) expect(text, k).toContain(k);
      // the command written out as one line masks the same
      const line = maskCredentialsInText(c.argv!.join(' '));
      for (const s of c.secrets) expect(line, s).not.toContain(s);
      for (const k of c.keep) expect(line, k).toContain(k);
    });
  }

  for (const c of corpus.cases.filter(x => x.command)) {
    it(`report masker, command string: ${c.name}`, () => {
      const out = maskCredentialsInText(c.command!);
      for (const s of c.secrets) expect(out, s).not.toContain(s);
      for (const k of c.keep) expect(out, k).toContain(k);
    });
  }
});
