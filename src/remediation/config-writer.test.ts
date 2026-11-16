import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { writeFile, readFile, mkdir, rm, stat, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  updateEnvFile,
  updateJsonFile,
  updateYamlFile,
  updateTomlFile,
  chmodFile,
  updateConfigValue,
  fixFirstConfig,
  restrictFilesToOwner,
  fixEveryConfig,
} from './config-writer.js';
import type { ParsedConfig } from '../core/types.js';
import { loadConfig } from '../core/config-loader.js';

const TEST_DIR = join(tmpdir(), 'vaso-config-writer-test');

beforeEach(async () => {
  await mkdir(TEST_DIR, { recursive: true });
});

afterEach(async () => {
  await rm(TEST_DIR, { recursive: true, force: true });
});

describe('updateEnvFile', () => {
  it('updates an existing key', async () => {
    const filePath = join(TEST_DIR, '.env');
    await writeFile(filePath, 'HTTP_HOST=0.0.0.0\nHTTP_PORT=8080\n');

    await updateEnvFile(filePath, 'HTTP_HOST', '127.0.0.1');

    const content = await readFile(filePath, 'utf-8');
    expect(content).toContain('HTTP_HOST=127.0.0.1');
    expect(content).toContain('HTTP_PORT=8080');
  });

  it('preserves comments and blank lines', async () => {
    const filePath = join(TEST_DIR, '.env');
    await writeFile(filePath, '# Server config\nHTTP_HOST=0.0.0.0\n\n# Port\nHTTP_PORT=8080\n');

    await updateEnvFile(filePath, 'HTTP_HOST', '127.0.0.1');

    const content = await readFile(filePath, 'utf-8');
    expect(content).toContain('# Server config');
    expect(content).toContain('# Port');
    expect(content).toContain('HTTP_HOST=127.0.0.1');
  });

  it('appends a new key if not found', async () => {
    const filePath = join(TEST_DIR, '.env');
    await writeFile(filePath, 'HTTP_PORT=8080\n');

    await updateEnvFile(filePath, 'HTTP_HOST', '127.0.0.1');

    const content = await readFile(filePath, 'utf-8');
    expect(content).toContain('HTTP_HOST=127.0.0.1');
    expect(content).toContain('HTTP_PORT=8080');
  });

  it('inserts before trailing blank lines', async () => {
    const filePath = join(TEST_DIR, '.env');
    await writeFile(filePath, 'KEY=val\n\n\n');

    await updateEnvFile(filePath, 'NEW_KEY', 'new_val');

    const lines = (await readFile(filePath, 'utf-8')).split('\n');
    const newKeyIndex = lines.findIndex(l => l.startsWith('NEW_KEY'));
    expect(newKeyIndex).toBeGreaterThan(0);
    expect(lines[newKeyIndex]).toBe('NEW_KEY=new_val');
  });

  it('rewrites the assignment the loader reads: the last one, `export KEY=` included', async () => {
    const filePath = join(TEST_DIR, '.env');
    await writeFile(filePath, 'NODE_ENV=production\nexport NODE_ENV=development\nOTHER=1\n');

    await updateEnvFile(filePath, 'NODE_ENV', 'production');

    const content = await readFile(filePath, 'utf-8');
    expect(content).toBe('NODE_ENV=production\nexport NODE_ENV=production\nOTHER=1\n');
    // The loaded value is the fixed one
    const loaded = await loadConfig(filePath);
    expect(loaded.data.NODE_ENV).toBe('production');
  });

  it('a duplicate earlier assignment no longer hides the effective one', async () => {
    const filePath = join(TEST_DIR, '.env');
    await writeFile(filePath, 'HOST=127.0.0.1\nHOST=0.0.0.0\n');
    await updateEnvFile(filePath, 'HOST', '127.0.0.1');
    expect((await loadConfig(filePath)).data.HOST).toBe('127.0.0.1');
  });
});

describe('updateJsonFile', () => {
  it('sets a top-level key', async () => {
    const filePath = join(TEST_DIR, 'config.json');
    await writeFile(filePath, JSON.stringify({ sandbox: false }, null, 2) + '\n');

    await updateJsonFile(filePath, 'sandbox', true);

    const data = JSON.parse(await readFile(filePath, 'utf-8'));
    expect(data.sandbox).toBe(true);
  });

  it('sets a nested key', async () => {
    const filePath = join(TEST_DIR, 'config.json');
    await writeFile(filePath, JSON.stringify({ gateway: { host: '0.0.0.0' } }, null, 2) + '\n');

    await updateJsonFile(filePath, 'gateway.host', '127.0.0.1');

    const data = JSON.parse(await readFile(filePath, 'utf-8'));
    expect(data.gateway.host).toBe('127.0.0.1');
  });

  it('creates intermediate objects for new nested keys', async () => {
    const filePath = join(TEST_DIR, 'config.json');
    await writeFile(filePath, JSON.stringify({}, null, 2) + '\n');

    await updateJsonFile(filePath, 'tools.exec.denyList', ['rm', 'curl']);

    const data = JSON.parse(await readFile(filePath, 'utf-8'));
    expect(data.tools.exec.denyList).toEqual(['rm', 'curl']);
  });

  it('preserves indentation style', async () => {
    const filePath = join(TEST_DIR, 'config.json');
    await writeFile(filePath, JSON.stringify({ key: 'val' }, null, 4) + '\n');

    await updateJsonFile(filePath, 'key', 'new');

    const content = await readFile(filePath, 'utf-8');
    // Should use 4-space indent
    expect(content).toContain('    "key"');
  });
});

describe('updateYamlFile', () => {
  it('sets a nested value', async () => {
    const filePath = join(TEST_DIR, 'config.yaml');
    await writeFile(filePath, 'gateway:\n  host: "0.0.0.0"\n  port: 18789\n');

    await updateYamlFile(filePath, 'gateway.host', '127.0.0.1');

    const content = await readFile(filePath, 'utf-8');
    expect(content).toContain('127.0.0.1');
    expect(content).toContain('port: 18789');
  });

  it('creates new nested keys', async () => {
    const filePath = join(TEST_DIR, 'config.yaml');
    await writeFile(filePath, 'existing: true\n');

    await updateYamlFile(filePath, 'rateLimit.max', 60);

    const content = await readFile(filePath, 'utf-8');
    expect(content).toContain('existing: true');
    expect(content).toContain('rateLimit');
    expect(content).toContain('max: 60');
  });
});

describe('updateTomlFile', () => {
  it('sets a nested value', async () => {
    const filePath = join(TEST_DIR, 'config.toml');
    await writeFile(filePath, '[secrets]\nencrypt = false\n');

    await updateTomlFile(filePath, 'secrets.encrypt', true);

    const content = await readFile(filePath, 'utf-8');
    expect(content).toContain('encrypt = true');
  });

  it('adds a new section and key', async () => {
    const filePath = join(TEST_DIR, 'config.toml');
    await writeFile(filePath, '[server]\nport = 3000\n');

    await updateTomlFile(filePath, 'runtime.sandbox', 'firejail');

    const content = await readFile(filePath, 'utf-8');
    expect(content).toContain('firejail');
    expect(content).toContain('port = 3000');
  });

  it('edits the one key line in place, keeping comments and float formatting', async () => {
    const filePath = join(TEST_DIR, 'config.toml');
    const before = [
      '# ZeroClaw config',
      'schema_version = 3',
      'temperature = 1.0',
      '',
      '[gateway]',
      '# bind address',
      'host = "127.0.0.1"',
      'require_pairing = false # TODO re-enable',
      'paths = [',
      '  "a", # first',
      '  "b",',
      ']',
      '',
      '# risk profiles',
      '[risk_profiles.default]',
      'level = "full"',
      '',
    ].join('\n');
    await writeFile(filePath, before);

    await updateTomlFile(filePath, 'gateway.require_pairing', true);
    let content = await readFile(filePath, 'utf-8');
    expect(content).toBe(before.replace('require_pairing = false # TODO re-enable', 'require_pairing = true # TODO re-enable'));

    // A key absent from an existing table goes under that table's header
    await updateTomlFile(filePath, 'gateway.allow_public_bind', false);
    content = await readFile(filePath, 'utf-8');
    expect(content).toContain(']\nallow_public_bind = false\n\n# risk profiles');
    expect(content).toContain('temperature = 1.0');

    // A missing table is appended; everything else stays byte-identical
    await updateTomlFile(filePath, 'secrets.encrypt', true);
    content = await readFile(filePath, 'utf-8');
    expect(content.endsWith('level = "full"\n\n[secrets]\nencrypt = true\n')).toBe(true);
    expect(content).toContain('# bind address');

    // Dotted key inside a table
    await writeFile(filePath, '[agents.bot]\nworkspace.unrestricted_filesystem = true # yolo\n');
    await updateTomlFile(filePath, 'agents.bot.workspace.unrestricted_filesystem', false);
    expect(await readFile(filePath, 'utf-8')).toBe('[agents.bot]\nworkspace.unrestricted_filesystem = false # yolo\n');
  });

  it('replaces a multi-line array value and falls back to a full rewrite for inline tables', async () => {
    const filePath = join(TEST_DIR, 'config.toml');
    await writeFile(filePath, '[p]\nroots = [\n  "/",\n]\nlevel = "x"\n');
    await updateTomlFile(filePath, 'p.roots', ['/srv']);
    expect(await readFile(filePath, 'utf-8')).toBe('[p]\nroots = [ "/srv" ]\nlevel = "x"\n');

    await writeFile(filePath, '# c\n[gateway]\ntls = { enabled = false }\n');
    await updateTomlFile(filePath, 'gateway.tls.enabled', true);
    const { parse } = await import('smol-toml');
    expect(parse(await readFile(filePath, 'utf-8'))).toEqual({ gateway: { tls: { enabled: true } } });
  });
});

describe('chmodFile', () => {
  it('sets file permissions', async () => {
    const filePath = join(TEST_DIR, 'secret');
    await writeFile(filePath, 'secret-data');
    await chmod(filePath, 0o644);

    await chmodFile(filePath, 0o600);

    const stats = await stat(filePath);
    expect(stats.mode & 0o777).toBe(0o600);
  });
});

describe('restrictFilesToOwner', () => {
  it('names files and directories separately in its message', async () => {
    const file = join(TEST_DIR, 'token.json');
    const dir = join(TEST_DIR, 'session-state');
    await writeFile(file, '{}');
    await chmod(file, 0o644);
    await mkdir(dir);
    await chmod(dir, 0o755);

    const result = await restrictFilesToOwner('POL-003', [file, dir]);
    expect(result.message).toBe('Removed group/other access from 1 file(s) and 1 directory');
    expect((await stat(dir)).mode & 0o777).toBe(0o700);
  });

  it('says file(s) only when only files changed', async () => {
    const file = join(TEST_DIR, 'auth.json');
    await writeFile(file, '{}');
    await chmod(file, 0o640);
    const result = await restrictFilesToOwner('POL-003', [file, join(TEST_DIR, 'missing.json')]);
    expect(result.message).toBe('Removed group/other access from 1 file(s)');
  });
});

describe('updateConfigValue dispatcher', () => {
  it('routes to env writer', async () => {
    const filePath = join(TEST_DIR, '.env');
    await writeFile(filePath, 'HTTP_HOST=0.0.0.0\n');

    const config: ParsedConfig = {
      raw: 'HTTP_HOST=0.0.0.0\n',
      format: 'env',
      filePath,
      data: { HTTP_HOST: '0.0.0.0' },
    };

    await updateConfigValue(config, 'HTTP_HOST', '127.0.0.1');

    const content = await readFile(filePath, 'utf-8');
    expect(content).toContain('HTTP_HOST=127.0.0.1');
  });

  it('routes to json writer', async () => {
    const filePath = join(TEST_DIR, 'config.json');
    await writeFile(filePath, '{"sandbox": false}\n');

    const config: ParsedConfig = {
      raw: '{"sandbox": false}\n',
      format: 'json',
      filePath,
      data: { sandbox: false },
    };

    await updateConfigValue(config, 'sandbox', true);

    const data = JSON.parse(await readFile(filePath, 'utf-8'));
    expect(data.sandbox).toBe(true);
  });

  it('routes to yaml writer', async () => {
    const filePath = join(TEST_DIR, 'config.yaml');
    await writeFile(filePath, 'sandbox: false\n');

    const config: ParsedConfig = {
      raw: 'sandbox: false\n',
      format: 'yaml',
      filePath,
      data: { sandbox: false },
    };

    await updateConfigValue(config, 'sandbox', true);

    const content = await readFile(filePath, 'utf-8');
    expect(content).toContain('sandbox: true');
  });

  it('routes to toml writer', async () => {
    const filePath = join(TEST_DIR, 'config.toml');
    await writeFile(filePath, 'sandbox = false\n');

    const config: ParsedConfig = {
      raw: 'sandbox = false\n',
      format: 'toml',
      filePath,
      data: { sandbox: false },
    };

    await updateConfigValue(config, 'sandbox', true);

    const content = await readFile(filePath, 'utf-8');
    expect(content).toContain('sandbox = true');
  });

  it('throws for unknown format', async () => {
    const config: ParsedConfig = {
      raw: '',
      format: 'unknown',
      filePath: '/dev/null',
      data: {},
    };

    await expect(updateConfigValue(config, 'key', 'val')).rejects.toThrow('Cannot write to config format');
  });
});

describe('multi-file fixes with a file vaso fix won\'t write', () => {
  it('fixEveryConfig writes the others and names the refused one; all refused → not applied, refused listed', async () => {
    const { symlink } = await import('node:fs/promises');
    const real = join(TEST_DIR, 'real.json');
    const second = join(TEST_DIR, 'agent-config-code.json');
    await writeFile(real, JSON.stringify({ loadExternalMcpConfigs: true }));
    await writeFile(second, JSON.stringify({ loadExternalMcpConfigs: true }));
    await symlink(real, join(TEST_DIR, 'config.json'));
    const cfg = (filePath: string): ParsedConfig => ({ filePath, format: 'json', raw: '', data: { loadExternalMcpConfigs: true } });
    const spec = { checkId: 'ABA-010', path: 'loadExternalMcpConfigs', value: false, message: 'Set loadExternalMcpConfigs to false' };
    const r = await fixEveryConfig([cfg(join(TEST_DIR, 'config.json')), cfg(second)], spec);
    expect(r).toMatchObject({ applied: true, refused: [join(TEST_DIR, 'config.json')] });
    expect(r.message).toBe(`Set loadExternalMcpConfigs to false — not changed: ${join(TEST_DIR, 'config.json')} is a symlink`);
    expect(JSON.parse(await readFile(second, 'utf-8'))).toEqual({ loadExternalMcpConfigs: false });
    expect(JSON.parse(await readFile(real, 'utf-8'))).toEqual({ loadExternalMcpConfigs: true });
    const none = await fixEveryConfig([cfg(join(TEST_DIR, 'config.json'))], spec);
    expect(none).toMatchObject({ applied: false, refused: [join(TEST_DIR, 'config.json')] });
    expect(none.alreadyDone).toBeFalsy();
  });

  it('restrictFilesToOwner lists refused paths, not other failures', async () => {
    const { symlink } = await import('node:fs/promises');
    const file = join(TEST_DIR, 'a.json');
    await writeFile(file, '{}');
    await chmod(file, 0o644);
    await symlink(file, join(TEST_DIR, 'l.json'));
    const r = await restrictFilesToOwner('POL-003', [join(TEST_DIR, 'l.json')]);
    expect(r).toMatchObject({ applied: false, refused: [join(TEST_DIR, 'l.json')] });
  });
});

describe('fixFirstConfig idempotence', () => {
  it('does not report a fix as applied when the file already holds the value', async () => {
    const { mkdtemp, writeFile: wf, rm: rmrf } = await import('node:fs/promises');
    const { tmpdir } = await import('node:os');
    const { join: j } = await import('node:path');
    const dir = await mkdtemp(j(tmpdir(), 'vaso-idem-'));
    const file = j(dir, 'openclaw.json');
    await wf(file, JSON.stringify({ gateway: { auth: { bypass: false } } }));
    // The scan saw bypass: true (stale snapshot); the file was fixed since
    const stale = { filePath: file, format: 'json' as const, raw: '', data: { gateway: { auth: { bypass: true } } } };
    const r = await fixFirstConfig([stale], { checkId: 'CFG-012', path: 'gateway.auth.bypass', value: false, message: 'Set gateway.auth.bypass to false' });
    expect(r.applied).toBe(false);
    expect(r.message).toContain('already set');
    await rmrf(dir, { recursive: true, force: true });
  });
});

describe('key paths with a dot inside a key name', () => {
  it('TOML: edits the quoted table in place, never adds a [a.b.c] split table', async () => {
    const filePath = join(TEST_DIR, 'config.toml');
    await writeFile(filePath, '[risk_profiles."prod.v2"]\nlevel = "full"\nworkspace_only = false\n');
    await updateTomlFile(filePath, ['risk_profiles', 'prod.v2', 'level'], 'supervised');
    const content = await readFile(filePath, 'utf-8');
    expect(content).toBe('[risk_profiles."prod.v2"]\nlevel = "supervised"\nworkspace_only = false\n');
  });

  it('TOML: a new table for a dotted key is written with a quoted key', async () => {
    const filePath = join(TEST_DIR, 'config.toml');
    await writeFile(filePath, 'schema_version = 3\n');
    await updateTomlFile(filePath, ['risk_profiles', 'prod.v2', 'level'], 'supervised');
    const content = await readFile(filePath, 'utf-8');
    expect(content).toContain('[risk_profiles."prod.v2"]\nlevel = "supervised"');
    const { parse } = await import('smol-toml');
    expect(parse(content)).toEqual({ schema_version: 3, risk_profiles: { 'prod.v2': { level: 'supervised' } } });
  });

  it('TOML: a dotted string path still splits on dots', async () => {
    const filePath = join(TEST_DIR, 'config.toml');
    await writeFile(filePath, '[risk_profiles.default]\nlevel = "full"\n');
    await updateTomlFile(filePath, 'risk_profiles.default.level', 'supervised');
    expect(await readFile(filePath, 'utf-8')).toBe('[risk_profiles.default]\nlevel = "supervised"\n');
  });

  it('JSON and YAML: segments address a key containing a dot', async () => {
    const jsonPath = join(TEST_DIR, 'settings.json');
    await writeFile(jsonPath, JSON.stringify({ accountScopes: { 'dot.ted': { localToolPermission: 'always' } } }, null, 2));
    await updateJsonFile(jsonPath, ['accountScopes', 'dot.ted', 'localToolPermission'], 'ask');
    expect(JSON.parse(await readFile(jsonPath, 'utf-8'))).toEqual({ accountScopes: { 'dot.ted': { localToolPermission: 'ask' } } });

    const yamlPath = join(TEST_DIR, 'config.yaml');
    await writeFile(yamlPath, 'profiles:\n  a.b:\n    mode: off\n');
    await updateYamlFile(yamlPath, ['profiles', 'a.b', 'mode'], 'manual');
    const YAML = (await import('yaml')).default;
    expect(YAML.parse(await readFile(yamlPath, 'utf-8'))).toEqual({ profiles: { 'a.b': { mode: 'manual' } } });
  });

  it('fixFirstConfig sees a segment path already set', async () => {
    const filePath = join(TEST_DIR, 'settings.json');
    await writeFile(filePath, JSON.stringify({ accountScopes: { 'dot.ted': { localToolPermission: 'ask' } } }));
    const stale = { filePath, format: 'json' as const, raw: '', data: {} };
    const r = await fixFirstConfig([stale], { checkId: 'GB-001', path: ['accountScopes', 'dot.ted', 'localToolPermission'], value: 'ask', message: 'Set' });
    expect(r.applied).toBe(false);
    expect(r.alreadyDone).toBe(true);
  });

  it('env files refuse a nested segment path', async () => {
    const filePath = join(TEST_DIR, '.env');
    await writeFile(filePath, 'A=1\n');
    const cfg: ParsedConfig = { filePath, format: 'env', raw: '', data: {} };
    await expect(updateConfigValue(cfg, ['approvals', 'mode'], 'manual')).rejects.toThrow(/nested key/);
    expect(await readFile(filePath, 'utf-8')).toBe('A=1\n');
  });
});

