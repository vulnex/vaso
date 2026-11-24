import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { chmod, mkdtemp, rm, stat, symlink, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadUserPlugins, getLoadedPlugins, _resetForTesting, registeredAnything } from './loader.js';

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

describe('plugin meta and partial registration', () => {
  it('ignores non-string meta values and keeps the file name', async () => {
    await writeFile(join(tempDir, 'odd-meta.mjs'), `
      export default { meta: { name: { x: 1 }, version: 3, description: ['d'] }, register() {} };
    `);
    const [p] = await loadUserPlugins(tempDir);
    expect(p.name).toBe('odd-meta');
    expect(p.version).toBeUndefined();
    expect(p.description).toBeUndefined();
  });

  it('records what a plugin registered before register() threw', async () => {
    await writeFile(join(tempDir, 'half.mjs'), `
      export default {
        register(api) {
          api.registerCheck({ id: 'HALF-001', name: 'h', category: 'config', severity: 'info', description: 'd', async run() { return []; } });
          throw new Error('late failure');
        },
      };
    `);
    const [p] = await loadUserPlugins(tempDir);
    expect(p.status).toBe('error');
    expect(registeredAnything(p)).toBe(true);
  });
});

/**
 * dt25 g8-F1: plugin code someone else could have written is refused — never
 * imported — like ~/.vaso/trusted-projects and ~/.vaso/rules.
 */
describe.runIf(process.platform !== 'win32')('loadUserPlugins refuses plugins others can write', () => {
  const marker = (name: string) => `
    import { writeFileSync } from 'node:fs';
    writeFileSync(process.env.VASO_PLUGIN_MARKER_DIR + '/' + ${JSON.stringify(name)}, 'ran');
    export default { register() {} };
  `;
  let pluginDir: string;
  beforeEach(async () => {
    pluginDir = join(tempDir, 'plugins');
    await mkdir(pluginDir, { mode: 0o700 });
    process.env.VASO_PLUGIN_MARKER_DIR = tempDir;
  });
  afterEach(() => { delete process.env.VASO_PLUGIN_MARKER_DIR; });

  const ran = async (name: string) => stat(join(tempDir, name)).then(() => true, () => false);

  it('loads an owner-only plugin', async () => {
    await writeFile(join(pluginDir, 'ok.mjs'), marker('ok'), { mode: 0o600 });
    const [p] = await loadUserPlugins(pluginDir);
    expect(p.status).toBe('loaded');
    expect(await ran('ok')).toBe(true);
  });

  it('refuses a world-writable plugin file', async () => {
    const f = join(pluginDir, 'ww.mjs');
    await writeFile(f, marker('ww'));
    await chmod(f, 0o666);
    const [p] = await loadUserPlugins(pluginDir);
    expect(p.status).toBe('error');
    expect(p.error).toMatch(/^refused: .*ww\.mjs is writable by group or others — not loaded/);
    expect(await ran('ww')).toBe(false);
  });

  it('refuses every plugin in a world-writable plugins directory', async () => {
    await writeFile(join(pluginDir, 'a.mjs'), marker('a'), { mode: 0o600 });
    await mkdir(join(pluginDir, 'b'));
    await writeFile(join(pluginDir, 'b', 'index.mjs'), marker('b'), { mode: 0o600 });
    await chmod(pluginDir, 0o777);
    const result = await loadUserPlugins(pluginDir);
    expect(result.map(p => p.status)).toEqual(['error', 'error']);
    expect(result[0].error).toContain(`${pluginDir} is writable by group or others — the plugins in ${pluginDir} are not loaded`);
    expect(await ran('a')).toBe(false);
    expect(await ran('b')).toBe(false);
  });

  it('refuses a directory plugin whose own folder others can write', async () => {
    await mkdir(join(pluginDir, 'd'));
    await writeFile(join(pluginDir, 'd', 'index.mjs'), marker('d'), { mode: 0o600 });
    await chmod(join(pluginDir, 'd'), 0o777);
    const [p] = await loadUserPlugins(pluginDir);
    expect(p.status).toBe('error');
    expect(p.error).toContain('is writable by group or others');
    expect(await ran('d')).toBe(false);
  });

  it('refuses a link to a plugin in a world-writable (non-sticky) directory', async () => {
    const open = join(tempDir, 'open');
    await mkdir(open);
    await writeFile(join(open, 'real.mjs'), marker('l'), { mode: 0o600 });
    await chmod(open, 0o777);
    await symlink(join(open, 'real.mjs'), join(pluginDir, 'l.mjs'));
    const [p] = await loadUserPlugins(pluginDir);
    expect(p.status).toBe('error');
    expect(p.error).toMatch(/links to .*real\.mjs, in a directory group or others can write/);
    expect(await ran('l')).toBe(false);
  });
});
