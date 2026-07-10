import { describe, it, expect } from 'vitest';
import { loadConfig, captureConfigLoadErrors } from './config-loader.js';
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
    console.log(`[loadConfig] JSON → format: ${config.format}, data:`, JSON.stringify(config.data));
    expect(config.format).toBe('json');
    expect(config.data).toEqual({ gateway: { host: '0.0.0.0', port: 18789 } });
    await cleanup();
  });

  it('parses YAML config', async () => {
    await setup();
    const filePath = join(TEST_DIR, 'config.yaml');
    await writeFile(filePath, 'gateway:\n  host: 127.0.0.1\n  port: 18789\n');

    const config = await loadConfig(filePath);
    console.log(`[loadConfig] YAML → format: ${config.format}, data:`, JSON.stringify(config.data));
    expect(config.format).toBe('yaml');
    expect(config.data).toEqual({ gateway: { host: '127.0.0.1', port: 18789 } });
    await cleanup();
  });

  it('parses .env config', async () => {
    await setup();
    const filePath = join(TEST_DIR, '.env');
    await writeFile(filePath, 'API_KEY=sk-test123\nDEBUG=true\n# comment\n');

    const config = await loadConfig(filePath);
    console.log(`[loadConfig] .env → format: ${config.format}, data:`, JSON.stringify(config.data));
    expect(config.format).toBe('env');
    expect(config.data).toEqual({ API_KEY: 'sk-test123', DEBUG: 'true' });
    await cleanup();
  });

  it('handles quoted .env values', async () => {
    await setup();
    const filePath = join(TEST_DIR, '.env');
    await writeFile(filePath, 'KEY="hello world"\nKEY2=\'single quoted\'\n');

    const config = await loadConfig(filePath);
    console.log(`[loadConfig] quoted .env → data:`, JSON.stringify(config.data));
    expect(config.data).toEqual({ KEY: 'hello world', KEY2: 'single quoted' });
    await cleanup();
  });

  it('parses TOML config', async () => {
    await setup();
    const filePath = join(TEST_DIR, 'config.toml');
    await writeFile(filePath, '[server]\nhost = "127.0.0.1"\nport = 3000\n');

    const config = await loadConfig(filePath);
    expect(config.format).toBe('toml');
    expect(config.data).toEqual({ server: { host: '127.0.0.1', port: 3000 } });
    await cleanup();
  });

  it('preserves raw content', async () => {
    await setup();
    const content = '{"test": true}';
    const filePath = join(TEST_DIR, 'raw.json');
    await writeFile(filePath, content);

    const config = await loadConfig(filePath);
    console.log(`[loadConfig] raw preserved → filePath: ${config.filePath}, raw: "${config.raw}"`);
    expect(config.raw).toBe(content);
    expect(config.filePath).toBe(filePath);
    await cleanup();
  });
});

describe('captureConfigLoadErrors', () => {
  it('records a parse failure for a known format and still throws', async () => {
    await setup();
    const filePath = join(TEST_DIR, 'broken.json');
    await writeFile(filePath, '{ "gateway": ');

    const { result, loadErrors } = await captureConfigLoadErrors(async () => {
      try {
        await loadConfig(filePath);
        return 'no-throw';
      } catch {
        return 'threw';
      }
    });

    expect(result).toBe('threw');
    expect(loadErrors).toHaveLength(1);
    expect(loadErrors[0].filePath).toBe(filePath);
    expect(loadErrors[0].stage).toBe('parse');
    await cleanup();
  });

  it('does not record a missing file (probing is normal)', async () => {
    const { loadErrors } = await captureConfigLoadErrors(async () => {
      await expect(loadConfig(join(TEST_DIR, 'does-not-exist.json'))).rejects.toThrow();
    });
    expect(loadErrors).toHaveLength(0);
  });

  it('records unknown-format content no parser accepts, returning empty data', async () => {
    await setup();
    const filePath = join(TEST_DIR, 'config.conf');
    // Tab-indented brace soup: rejected by JSON, YAML, and TOML alike.
    await writeFile(filePath, '{{{\n\t::: not = [ config\n');

    const { result, loadErrors } = await captureConfigLoadErrors(() => loadConfig(filePath));

    expect(result.data).toEqual({});
    expect(loadErrors).toHaveLength(1);
    expect(loadErrors[0].stage).toBe('parse');
    await cleanup();
  });

  it('does not record an empty unknown-format file', async () => {
    await setup();
    const filePath = join(TEST_DIR, 'empty.conf');
    await writeFile(filePath, '');

    const { result, loadErrors } = await captureConfigLoadErrors(() => loadConfig(filePath));

    expect(result.data).toEqual({});
    expect(loadErrors).toHaveLength(0);
    await cleanup();
  });

  it('isolates captures across concurrent contexts', async () => {
    await setup();
    const brokenA = join(TEST_DIR, 'a.json');
    const brokenB = join(TEST_DIR, 'b.json');
    await writeFile(brokenA, 'not json');
    await writeFile(brokenB, 'also not json');

    const swallow = (p: string) => loadConfig(p).catch(() => undefined);
    const [a, b] = await Promise.all([
      captureConfigLoadErrors(() => swallow(brokenA)),
      captureConfigLoadErrors(() => swallow(brokenB)),
    ]);

    expect(a.loadErrors.map(e => e.filePath)).toEqual([brokenA]);
    expect(b.loadErrors.map(e => e.filePath)).toEqual([brokenB]);
    await cleanup();
  });

  it('records nothing outside a capture context and does not throw', async () => {
    await setup();
    const filePath = join(TEST_DIR, 'broken2.json');
    await writeFile(filePath, '{ nope');

    await expect(loadConfig(filePath)).rejects.toThrow();
    await cleanup();
  });
});
