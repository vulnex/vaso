import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadUserPlugins, getLoadedPlugins, _resetForTesting } from './loader.js';

let tempDir: string;

beforeEach(async () => {
  _resetForTesting();
  tempDir = await mkdtemp(join(tmpdir(), 'vaso-plugin-test-'));
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

describe('loadUserPlugins', () => {
  it('returns empty array for nonexistent directory', async () => {
    const result = await loadUserPlugins(join(tempDir, 'nope'));
    expect(result).toEqual([]);
  });

  it('returns empty array for empty directory', async () => {
    const result = await loadUserPlugins(tempDir);
    expect(result).toEqual([]);
  });

  it('loads a valid single-file plugin', async () => {
    await writeFile(join(tempDir, 'my-check.mjs'), `
      export default {
        meta: { name: 'my-check', version: '1.0.0', description: 'A test check' },
        register(api) {
          api.registerCheck({
            id: 'USR-001',
            name: 'User Check',
            category: 'config',
            severity: 'info',
            description: 'A user-defined check',
            async run() {
              return { id: 'USR-001', name: 'User Check', category: 'config', severity: 'info', passed: true, message: 'OK' };
            }
          });
        }
      };
    `);

    const result = await loadUserPlugins(tempDir);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('my-check');
    expect(result[0].version).toBe('1.0.0');
    expect(result[0].description).toBe('A test check');
    expect(result[0].status).toBe('loaded');
    expect(result[0].registered.checks).toEqual(['USR-001']);
    expect(result[0].registered.adapters).toEqual([]);
    expect(result[0].registered.reporters).toEqual([]);
  });

  it('records broken plugin with syntax error as error', async () => {
    await writeFile(join(tempDir, 'broken.mjs'), `
      export default {
        register(api) {
          this is not valid javascript!!!
        }
      };
    `);

    const result = await loadUserPlugins(tempDir);
    expect(result).toHaveLength(1);
    expect(result[0].status).toBe('error');
    expect(result[0].error).toBeDefined();
    expect(result[0].name).toBe('broken');
  });

  it('records error for plugin missing register function', async () => {
    await writeFile(join(tempDir, 'no-register.mjs'), `
      export default {
        meta: { name: 'no-register' },
      };
    `);

    const result = await loadUserPlugins(tempDir);
    expect(result).toHaveLength(1);
    expect(result[0].status).toBe('error');
    expect(result[0].error).toContain('register()');
  });

  it('records duplicate check ID as error but plugin still partially loads', async () => {
    // First register a check directly so it occupies the ID
    await writeFile(join(tempDir, 'dupe.mjs'), `
      export default {
        meta: { name: 'dupe-plugin' },
        register(api) {
          api.registerCheck({
            id: 'DUPE-OK',
            name: 'OK Check',
            category: 'config',
            severity: 'info',
            description: 'This one succeeds',
            async run() { return { id: 'DUPE-OK', name: 'OK Check', category: 'config', severity: 'info', passed: true, message: 'OK' }; }
          });
          api.registerCheck({
            id: 'DUPE-OK',
            name: 'Duplicate Check',
            category: 'config',
            severity: 'info',
            description: 'This one duplicates',
            async run() { return { id: 'DUPE-OK', name: 'Duplicate Check', category: 'config', severity: 'info', passed: true, message: 'OK' }; }
          });
        }
      };
    `);

    const result = await loadUserPlugins(tempDir);
    expect(result).toHaveLength(1);
    expect(result[0].status).toBe('error');
    expect(result[0].error).toContain('DUPE-OK');
    // First check was registered successfully
    expect(result[0].registered.checks).toContain('DUPE-OK');
  });

  it('resolves directory plugin via package.json main', async () => {
    const pluginDir = join(tempDir, 'dir-plugin');
    await mkdir(pluginDir, { recursive: true });
    await writeFile(join(pluginDir, 'package.json'), JSON.stringify({ main: 'entry.mjs' }));
    await writeFile(join(pluginDir, 'entry.mjs'), `
      export default {
        meta: { name: 'dir-plugin' },
        register(api) {
          api.registerReporter('custom-fmt', () => ({
            format: 'custom-fmt',
            render() { return 'custom'; }
          }));
        }
      };
    `);

    const result = await loadUserPlugins(tempDir);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('dir-plugin');
    expect(result[0].status).toBe('loaded');
    expect(result[0].registered.reporters).toEqual(['custom-fmt']);
  });

  it('resolves directory plugin via index.mjs', async () => {
    const pluginDir = join(tempDir, 'idx-plugin');
    await mkdir(pluginDir, { recursive: true });
    await writeFile(join(pluginDir, 'index.mjs'), `
      export default {
        meta: { name: 'idx-plugin' },
        register(api) {}
      };
    `);

    const result = await loadUserPlugins(tempDir);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('idx-plugin');
    expect(result[0].status).toBe('loaded');
  });

  it('resolves directory plugin via index.js', async () => {
    const pluginDir = join(tempDir, 'js-plugin');
    await mkdir(pluginDir, { recursive: true });
    await writeFile(join(pluginDir, 'index.js'), `
      module.exports = {
        meta: { name: 'js-plugin' },
        register(api) {}
      };
    `);

    const result = await loadUserPlugins(tempDir);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('js-plugin');
    expect(result[0].status).toBe('loaded');
  });

  it('skips hidden files with dot prefix', async () => {
    await writeFile(join(tempDir, '.hidden.mjs'), `
      export default { register(api) {} };
    `);

    const result = await loadUserPlugins(tempDir);
    expect(result).toEqual([]);
  });

  it('skips files with underscore prefix', async () => {
    await writeFile(join(tempDir, '_disabled.mjs'), `
      export default { register(api) {} };
    `);

    const result = await loadUserPlugins(tempDir);
    expect(result).toEqual([]);
  });

  it('skips non-js files', async () => {
    await writeFile(join(tempDir, 'readme.txt'), 'not a plugin');
    await writeFile(join(tempDir, 'notes.md'), 'some notes');

    const result = await loadUserPlugins(tempDir);
    expect(result).toEqual([]);
  });

  it('awaits async register function', async () => {
    await writeFile(join(tempDir, 'async-plugin.mjs'), `
      export default {
        meta: { name: 'async-plugin' },
        async register(api) {
          await new Promise(r => setTimeout(r, 10));
          api.registerCheck({
            id: 'ASYNC-001',
            name: 'Async Check',
            category: 'config',
            severity: 'info',
            description: 'Registered asynchronously',
            async run() { return { id: 'ASYNC-001', name: 'Async Check', category: 'config', severity: 'info', passed: true, message: 'OK' }; }
          });
        }
      };
    `);

    const result = await loadUserPlugins(tempDir);
    expect(result).toHaveLength(1);
    expect(result[0].status).toBe('loaded');
    expect(result[0].registered.checks).toEqual(['ASYNC-001']);
  });

  it('getLoadedPlugins returns results from last load', async () => {
    expect(getLoadedPlugins()).toEqual([]);

    await writeFile(join(tempDir, 'plugin.mjs'), `
      export default {
        meta: { name: 'cached' },
        register(api) {}
      };
    `);

    await loadUserPlugins(tempDir);
    const cached = getLoadedPlugins();
    expect(cached).toHaveLength(1);
    expect(cached[0].name).toBe('cached');
  });

  it('handles plugin that throws during register', async () => {
    await writeFile(join(tempDir, 'thrower.mjs'), `
      export default {
        meta: { name: 'thrower' },
        register(api) {
          throw new Error('plugin init failed');
        }
      };
    `);

    const result = await loadUserPlugins(tempDir);
    expect(result).toHaveLength(1);
    expect(result[0].status).toBe('error');
    expect(result[0].error).toContain('plugin init failed');
  });
});
