import { describe, it, expect } from 'vitest';
import { loadConfig } from './config-loader.js';
import { writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const TEST_DIR = join(tmpdir(), 'vaso-config-test');

async function setup() {
  await mkdir(TEST_DIR, { recursive: true });
}

async function cleanup() {
  await rm(TEST_DIR, { recursive: true, force: true });
}

describe('loadConfig', () => {
  it('parses JSON config', async () => {
    await setup();
    const filePath = join(TEST_DIR, 'config.json');
    await writeFile(filePath, JSON.stringify({ gateway: { host: '0.0.0.0', port: 18789 } }));

    const config = await loadConfig(filePath);
    expect(config.format).toBe('json');
    expect(config.data).toEqual({ gateway: { host: '0.0.0.0', port: 18789 } });
    await cleanup();
  });

  it('parses YAML config', async () => {
    await setup();
    const filePath = join(TEST_DIR, 'config.yaml');
    await writeFile(filePath, 'gateway:\n  host: 127.0.0.1\n  port: 18789\n');

    const config = await loadConfig(filePath);
    expect(config.format).toBe('yaml');
    expect(config.data).toEqual({ gateway: { host: '127.0.0.1', port: 18789 } });
    await cleanup();
  });

  it('parses .env config', async () => {
    await setup();
    const filePath = join(TEST_DIR, '.env');
    await writeFile(filePath, 'API_KEY=sk-test123\nDEBUG=true\n# comment\n');

    const config = await loadConfig(filePath);
    expect(config.format).toBe('env');
    expect(config.data).toEqual({ API_KEY: 'sk-test123', DEBUG: 'true' });
    await cleanup();
  });

  it('handles quoted .env values', async () => {
    await setup();
    const filePath = join(TEST_DIR, '.env');
    await writeFile(filePath, 'KEY="hello world"\nKEY2=\'single quoted\'\n');

    const config = await loadConfig(filePath);
    expect(config.data).toEqual({ KEY: 'hello world', KEY2: 'single quoted' });
    await cleanup();
  });

  it('preserves raw content', async () => {
    await setup();
    const content = '{"test": true}';
    const filePath = join(TEST_DIR, 'raw.json');
    await writeFile(filePath, content);

    const config = await loadConfig(filePath);
    expect(config.raw).toBe(content);
    expect(config.filePath).toBe(filePath);
    await cleanup();
  });
});
