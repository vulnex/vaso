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
} from './config-writer.js';
import type { ParsedConfig } from '../core/types.js';

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
