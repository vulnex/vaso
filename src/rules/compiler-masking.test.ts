import { describe, it, expect } from 'vitest';
import { compileRule } from './compiler.js';
import type { DeclarativeRule } from './schema.js';
import type { CheckResult, ParsedConfig, ScanContext } from '../core/types.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { getReporter, reportFormats } from '../reporting/index.js';
import { credentialValuesIn, knownValueMasker, maskConfigValue } from '../reporting/serialize.js';

// A declarative rule quotes the user's config. Whatever the rule matched, a
// credential value in it is masked in every report format: a numeric PIN, an
// item of a credential-named array, an argv value on the line below its flag,
// an item of a `secrets:` list.

const settingsData = {
  env: { PIN: 1234567, DB_PASSWORD: 84736251, SERVICE_TOKENS: 'tok1', LOG_LEVEL: 'debug' },
  apiKeys: ['Hunter2Pass!word'],
  permissions: { allow: ['Read'] },
};
const settings: ParsedConfig = {
  raw: JSON.stringify(settingsData, null, 2),
  format: 'json', filePath: '/h/.claude/settings.json', data: settingsData,
};
const claudeJsonData = {
  mcpServers: { svc: { command: 'npx', args: ['-y', 'some-mcp@1.0.0', '--api-key', 'corgiBatteryHorse77', '--password', 'pw-Zebra-Moon-9'] } },
};
const claudeJson: ParsedConfig = {
  raw: JSON.stringify(claudeJsonData, null, 2),
  format: 'json', filePath: '/h/.claude.json', data: claudeJsonData,
};
const hermes: ParsedConfig = {
  raw: 'model:\n  provider: openrouter\n  api_key: 987654321012\npassword: 84736251\nsecrets:\n  - tokenInArray99\n',
  format: 'yaml', filePath: '/h/.hermes/config.yaml',
  data: { model: { provider: 'openrouter', api_key: 987654321012 }, password: 84736251, secrets: ['tokenInArray99'] },
};

const ctx = (): ScanContext => ({
  installation: { agent: 'claude-code', installDir: '/h/.claude', configFiles: [settings, claudeJson, hermes] },
  configs: [settings, claudeJson, hermes], platform: 'darwin', fs: new LocalFSProvider(),
});

const rule = (id: string, body: Partial<DeclarativeRule>): DeclarativeRule =>
  ({ id, name: id, category: 'config', severity: 'critical', description: 'd', ...body }) as DeclarativeRule;

const RULES: DeclarativeRule[] = [
  rule('ORG-A', { config: { path: 'env.PIN', operator: 'gt', value: 1 } }),
  rule('ORG-B', { config: { path: 'env', operator: 'exists' } }),
  rule('ORG-C', { config: { path: 'apiKeys.0', operator: 'matches', value: '^H' } }),
  rule('ORG-D', { config: { path: 'model.api_key', operator: 'exists' } }),
  rule('ORG-E', { config: { path: 'mcpServers', operator: 'exists' } }),
  rule('ORG-F', { pattern: { regex: 'corgi', target: 'configs', message: '{{match}} in {{snippet}}' } }),
  rule('ORG-G', { pattern: { regex: 'Zebra', target: 'configs' } }),
  rule('ORG-H', { pattern: { regex: 'tokenInArray|Hunter2|1234567|84736251|987654321012', target: 'configs' } }),
];
const SECRETS = ['1234567', '84736251', 'Hunter2Pass', '987654321012', 'corgiBatteryHorse77', 'pw-Zebra-Moon-9', 'tokenInArray99'];

describe('rule evidence never quotes a credential value', () => {
  it('in every report format', async () => {
    const results: CheckResult[] = [];
    for (const r of RULES) results.push(await compileRule(r).run(ctx()));
    for (const r of results) expect(r.passed, r.id).toBe(false);
    const scan = {
      timestamp: 't', totalScore: 0, totalGrade: 'F', fleetAverage: 0,
      summary: { critical: results.length, warning: 0, info: 0, passed: 0, total: results.length },
      agents: [{ agent: 'claude-code', score: 0, grade: 'F', installation: { agent: 'claude-code', installDir: '/h/.claude', configFiles: [] }, results }],
    };
    for (const format of reportFormats()) {
      const out = getReporter(format).render(scan as never);
      for (const secret of SECRETS) expect(out, `${format}: ${secret}`).not.toContain(secret);
    }
  });

  it('keeps the rest of the quoted value readable', async () => {
    const env = await compileRule(RULES[1]).run(ctx());
    expect(env.evidence![0].detail).toBe('env = {"PIN":"***","DB_PASSWORD":"***","SERVICE_TOKENS":"***","LOG_LEVEL":"debug"}');
    const servers = await compileRule(RULES[4]).run(ctx());
    expect(servers.evidence![0].detail).toContain('"--api-key","***","--password","***"');
    expect(servers.evidence![0].detail).toContain('some-mcp@1.0.0');
  });
});

describe('maskConfigValue / credentialValuesIn', () => {
  it('masks below a credential name, numbers included, and by path', () => {
    expect(maskConfigValue('apiKeys.0', 'Hunter2Pass!word')).toBe('***');
    expect(maskConfigValue('env.PIN', 1234567)).toBe('***');
    expect(maskConfigValue('credentials', { db: { user: 'u', port: 5432 } })).toEqual({ db: { user: '***', port: '***' } });
    expect(maskConfigValue('server.port', 8080)).toBe(8080);
    expect(maskConfigValue('session.timeout', 300)).toBe(300);
    expect(maskConfigValue('max_tokens', 4096)).toBe(4096);
    expect(maskConfigValue('env.GITHUB_TOKEN', '${GITHUB_TOKEN}')).toBe('${GITHUB_TOKEN}');
  });

  it('collects the values to mask in quoted lines', () => {
    const values = credentialValuesIn({ ...claudeJsonData, ...hermes.data });
    expect(values).toEqual(expect.arrayContaining(['corgiBatteryHorse77', 'pw-Zebra-Moon-9', '987654321012', '84736251', 'tokenInArray99']));
    expect(values).not.toContain('some-mcp@1.0.0');
    const mask = knownValueMasker(values);
    expect(mask('      "pw-Zebra-Moon-9",')).toBe('      "***",');
    // whole words only
    expect(mask('x84736251y 84736251')).toBe('x84736251y ***');
  });

  it('collects the words of a folded or plain multi-line scalar', () => {
    const values = credentialValuesIn({ api_key: 'FoldedPartOne11 FoldedPartTwo22', token: 'PlainMultiAaa44 PlainMultiBbb55' });
    const mask = knownValueMasker(values);
    expect(mask('    FoldedPartTwo22')).toBe('    ***');
    expect(mask('  PlainMultiAaa44')).toBe('  ***');
  });

  it('masks a value spelled with character escapes', () => {
    const mask = knownValueMasker(credentialValuesIn({ apiKeys: ['HunterTwoEsc99'], password: 'EscapedPw33' }));
    expect(mask('    "\\u0048unterTwoEsc99"')).toBe('    "***"');
    expect(mask('    "Hunter\\u0054woEsc99", "x"')).toBe('    "***", "x"');
    expect(mask('password: "Esc\\x61pedPw33" # note')).toBe('password: "***" # note');
    // an escape that isn't part of a value stays
    expect(mask('"\\u0041bc" HunterTwoEsc99x')).toBe('"\\u0041bc" HunterTwoEsc99x');
  });
});

describe('rule evidence on lines continuing a credential value', () => {
  const run = async (id: string, regex: string, target: 'configs' | 'skills', configs: ParsedConfig[], skillFiles: string[] = []) =>
    compileRule(rule(id, { pattern: { regex, target, message: 'hit {{match}} in {{snippet}}' } })).run({
      installation: { agent: 'hermes', installDir: '/h', configFiles: configs },
      configs, platform: 'darwin', fs: new LocalFSProvider(), skillFiles,
    });

  it('YAML folded and plain multi-line scalars, JSON escapes, TOML arrays and strings', async () => {
    const yaml: ParsedConfig = {
      raw: 'model:\n  provider: openrouter\n  api_key: >-\n    FoldedPartOne11\n    FoldedPartTwo22\ntoken:\n  PlainMultiAaa44\n  PlainMultiBbb55\n',
      format: 'yaml', filePath: '/h/config.yaml',
      data: { model: { provider: 'openrouter', api_key: 'FoldedPartOne11 FoldedPartTwo22' }, token: 'PlainMultiAaa44 PlainMultiBbb55' },
    };
    const json: ParsedConfig = {
      raw: '{\n  "apiKeys": [\n    "\\u0048unterTwoEsc99"\n  ]\n}\n', format: 'json', filePath: '/h/settings.json', data: { apiKeys: ['HunterTwoEsc99'] },
    };
    const r = await run('ORG-M1', 'Folded|PlainMulti|unterTwo|openrouter', 'configs', [yaml, json]);
    const text = JSON.stringify(r.evidence);
    for (const s of ['FoldedPart', 'PlainMulti', 'unterTwoEsc99']) expect(text).not.toContain(s);
    expect(text).toContain('openrouter');
  });

  it('skill files: values below `NAME = [` / `name = (` / `"password":`', async () => {
    const { mkdtemp, writeFile, rm } = await import('node:fs/promises');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const dir = await mkdtemp(join(tmpdir(), 'vaso-rule-skill-'));
    try {
      const py = join(dir, 'run.py');
      await writeFile(py, 'API_KEYS = [\n    "SkillPySecret99",\n]\npassword = (\n    "SkillPyPw42"\n)\nname = "SkillName"\n');
      const js = join(dir, 'config.json');
      await writeFile(js, '{\n  "apiKeys": [\n    "SkillArraySecret77"\n  ],\n  "password":\n    "SkillPwNextLine88",\n  "label": "SkillLabel"\n}\n');
      const r = await run('ORG-M2', 'Skill', 'skills', [], [py, js]);
      const text = JSON.stringify(r.evidence);
      for (const s of ['SkillPySecret99', 'SkillPyPw42', 'SkillArraySecret77', 'SkillPwNextLine88']) expect(text).not.toContain(s);
      expect(text).toContain('SkillName');
      expect(text).toContain('SkillLabel');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('skill files: an environment variable name read below a credential name stays readable', async () => {
    const { mkdtemp, writeFile, rm } = await import('node:fs/promises');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const dir = await mkdtemp(join(tmpdir(), 'vaso-rule-skill-'));
    try {
      const py = join(dir, 'run.py');
      await writeFile(py, 'password = (\n    os.environ.get("DB_PASSWORD") or "SkillFallbackPw55"\n)\nTOKENS = [\n    os.environ["T1"],\n    getenv(\'T2\'),\n    "SkillLiteralTok66",\n]\n');
      const r = await run('ORG-M3', 'environ|getenv|Skill', 'skills', [], [py]);
      const text = JSON.stringify(r.evidence);
      for (const s of ['os.environ.get(\\"DB_PASSWORD\\")', 'os.environ[\\"T1\\"]', "getenv('T2')"]) expect(text).toContain(s);
      for (const s of ['SkillFallbackPw55', 'SkillLiteralTok66']) expect(text).not.toContain(s);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('config rule details keep their brackets', () => {
  it('an object or a list under a credential name', async () => {
    const cfg: ParsedConfig = { raw: '', format: 'toml', filePath: '/h/c.toml', data: { credentials: { primary: { value: 'NestedCredQq77' } }, bearer_tokens: ['TomlArrSecret99'] } };
    const c = { installation: { agent: 'codex' as const, installDir: '/h', configFiles: [cfg] }, configs: [cfg], platform: 'darwin' as const, fs: new LocalFSProvider() };
    const creds = await compileRule(rule('ORG-N1', { config: { path: 'credentials', operator: 'exists' } })).run(c);
    const tokens = await compileRule(rule('ORG-N2', { config: { path: 'bearer_tokens', operator: 'exists' } })).run(c);
    const scan = {
      timestamp: 't', totalScore: 0, totalGrade: 'F', fleetAverage: 0,
      summary: { critical: 2, warning: 0, info: 0, passed: 0, total: 2 },
      agents: [{ agent: 'codex', score: 0, grade: 'F', installation: { agent: 'codex', installDir: '/h', configFiles: [] }, results: [creds, tokens] }],
    };
    const out = getReporter('json').render(scan as never);
    expect(out).toContain('credentials = {\\"primary\\":{\\"value\\":\\"***\\"}}');
    expect(out).toContain('bearer_tokens = [\\"***\\"]');
    expect(out).not.toMatch(/NestedCredQq77|TomlArrSecret99/);
  });
});
