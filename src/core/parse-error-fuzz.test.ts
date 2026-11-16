import { describe, it, expect } from 'vitest';
import YAML from 'yaml';
import { parse as parseToml } from 'smol-toml';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { parseErrorMessage } from './parse-error.js';
import { parseYamlSafe } from './yaml-safe.js';
import { parseTomlSafe } from './toml-safe.js';
import { parseJsonLenient } from './jsonc.js';
import { parseJson5 } from './json5.js';

function thrown(f: () => unknown): Error {
  try {
    f();
  } catch (err) {
    return err as Error;
  }
  throw new Error('did not throw');
}

/**
 * Every error each parser VASO uses can raise, for files whose values (and
 * keys) are planted secrets in every position: the message is one of the
 * fixed forms parseErrorMessage produces — nothing from the file.
 */
const SECRETS = ['hunter2!', 'sk-or-v1-Qw3nPLNT', 'P10z', 'pw9PLNT', 'xoxb-PLNT-77', 'ghp_PLNTabc'];
const PREFIXES = ['', '>', '|', '!', '&', '*', '%', '@', '`', '{', '[', '"', "'", ',', ':', '#', '- ', '? ', '>2-', '|+'];
const ALLOWED = [
  /^YAML syntax error \([a-z0-9 ]+\)(?: at line \d+, column \d+)?$/,
  /^YAML contains a self-referencing alias$/,
  /^found duplicate key(?: at line \d+)?$/,
  /^Invalid TOML document: [a-z0-9 ,.:-]+ at line \d+, column \d+$/,
  /^(?:(?:Expected property name or '\}'|Expected ',' or '\}' after property value|Expected ',' or '\]' after array element|Expected double-quoted property name|Expected ':' after property name|Bad control character in string literal|Bad escaped character|Bad Unicode escape|Unterminated string|Exponent part is missing a number|No number after minus sign|Unterminated fractional number) in JSON|Unexpected non-whitespace character after JSON)(?: at position \d+(?: \(line \d+ column \d+\))?)?$/,
  /^Unexpected end of JSON input$/,
  /^not valid JSON(?: at position \d+(?: \(line \d+ column \d+\))?)?$/,
  /^JSON5: [A-Za-z ,:'}\]\\]+ at line \d+$/,
];
const bare = (v: string) => v.replace(/\W/g, '');
const docs = (v: string): Array<[string, string]> => [
  ['yaml', `model:\n  api_key: ${v}\n  other: 1\n`],
  ['yaml', `${v}: 1\nx: [\n`],
  ['yaml', `a:\n  - ${v}\n - b\n`],
  ['yaml', `a: "${v}\nb: 1\n`],
  ['yaml', `a: !${bare(v)} x\n`],
  ['yaml', `a: !<${bare(v)}> x\n`],
  ['yaml', `a: 1\na: ${v}\n`],
  ['yaml', `!!omap\n- ${bare(v)}: 1\n- ${bare(v)}: 2\n`],
  ['yaml', `a: &${bare(v)} 1\nb: *${bare(v)}x\n`],
  ['yaml', `a: &${bare(v)} !t 1\n`],
  ['yaml', `\t${v}: 1\n`],
  ['yaml', `%${bare(v)} x\n---\na: 1\n`],
  ['toml', `[env]\nKEY = ${v}\n`],
  ['toml', `KEY = "${v}\nX = 1\n`],
  ['toml', `${v} = = 1\n`],
  ['toml', `[${v}\nX = 1\n`],
  ['toml', `K = "\\q${v}"\n`],
  ['json', `{"env": {"DB_PASSWORD": ${v}\n}}`],
  ['json', `{"a": "10", ${v}\n}`],
  ['json', `{"a": "10",\n${v}}`],
  ['json', `{"a": "${v}" "b": 1}`],
  ['json', `${v}`],
  ['json', `{"a": "${v}\u0001"}`],
  ['json', `[${v}`],
  ['json', `{"a": 1}${v}`],
  ['json', `{${v}: 1, }`],
  ['json', `{"a": -${v}}`],
  ['json', `{"a": "\\${v}"}`],
  ['json', `// c\n{"a": ${v}}`],
];
const parsers: Record<string, Array<(text: string) => unknown>> = {
  yaml: [t => parseYamlSafe(t), t => parseYamlSafe(t, { duplicateKeys: 'reject' }), t => YAML.parse(t), t => YAML.parse(t, { uniqueKeys: true })],
  toml: [t => parseTomlSafe(t), t => parseToml(t)],
  json: [t => parseJsonLenient(t), t => JSON.parse(t), t => parseJson5(t)],
};

describe('parse errors never carry config text (fuzz)', () => {
  it('yaml, smol-toml, JSON, JSONC and JSON5 messages are fixed forms with a position', () => {
    let checked = 0;
    const bad: string[] = [];
    for (const secret of SECRETS) {
      for (const prefix of PREFIXES) {
        for (const [kind, text] of docs(prefix + secret)) {
          for (const parse of parsers[kind]) {
            let err: unknown;
            try {
              parse(text);
              continue;
            } catch (e) {
              err = e;
            }
            checked++;
            const msg = parseErrorMessage(err);
            // and once more, as callers re-scrub a scrubbed message
            for (const m of [msg, parseErrorMessage(msg)]) {
              if (!ALLOWED.some(re => re.test(m)) || m.includes(secret.slice(0, 4))) bad.push(`${kind} ${JSON.stringify(text)} → ${m}`);
            }
          }
        }
      }
    }
    expect(checked).toBeGreaterThan(1000);
    expect(bad.slice(0, 20), `${bad.length} messages`).toEqual([]);
  });

  it('the reported shapes: a block-scalar-looking value, a short unquoted JSON value, the previous value', () => {
    const yaml = parseErrorMessage(thrown(() => parseYamlSafe('model:\n  api_key: >sk-or-v1-Qw3nPLANTED\n')));
    expect(yaml).toMatch(/^YAML syntax error \(.+\) at line 2, column \d+$/);
    expect(yaml).not.toContain('sk-or');
    const json = parseErrorMessage(thrown(() => JSON.parse('{"env": {"DB_PASSWORD": hunter2!\n}}')));
    expect(json).not.toMatch(/hunter|ASSWORD/);
    const prev = parseErrorMessage(thrown(() => JSON.parse('{"a": "10",\nP}')));
    expect(prev).not.toMatch(/10|'P'/);
    const gemini = parseErrorMessage(thrown(() => JSON.parse('// comment\n{"a": 1}')));
    expect(gemini).not.toMatch(/\/\/|comment/);
  });

  it('keeps messages that are no parser error', () => {
    expect(parseErrorMessage(new Error("ENOENT: no such file or directory, open '/x/y.json'"))).toBe("ENOENT: no such file or directory, open '/x/y.json'");
    expect(parseErrorMessage(new Error('YAML contains a self-referencing alias'))).toBe('YAML contains a self-referencing alias');
  });

  it('vaso rules validate prints no rule-file text', async () => {
    const { runRulesValidate } = await import('../commands/rules.js');
    const dir = await mkdtemp(join(tmpdir(), 'vaso-perr-rules-'));
    await writeFile(join(dir, 'r.yaml'), 'rules:\n  - id: ORG-1\n    password: >hunter2PLANTED\n');
    const out: string[] = [];
    const log = console.log;
    const error = console.error;
    console.log = (...a: unknown[]) => { out.push(a.join(' ')); };
    console.error = (...a: unknown[]) => { out.push(a.join(' ')); };
    const code = process.exitCode;
    try {
      await runRulesValidate(join(dir, 'r.yaml'), {});
      await runRulesValidate(join(dir, 'r.yaml'), { format: 'json' });
    } finally {
      console.log = log;
      console.error = error;
      process.exitCode = code;
      await rm(dir, { recursive: true, force: true });
    }
    expect(out.join('\n')).toMatch(/YAML syntax error/);
    expect(out.join('\n')).not.toContain('hunter2');
  });

  it('a snapshot that is not valid JSON', async () => {
    const { parseSnapshot } = await import('./snapshot-load.js');
    const err = thrown(() => parseSnapshot('{"files": {"/h/.env": {"content": hunter2PLANTED\n}}}', 'Snapshot file'));
    expect(err.message).toMatch(/^Snapshot file is not valid JSON: not valid JSON/);
    expect(err.message).not.toContain('hunter2');
  });
});
