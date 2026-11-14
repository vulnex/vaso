import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import type { MCPServerEntry } from './types.js';
import { launchTarget, packageScriptRun, resolveServerSources } from './source-resolver.js';
import { parseServerMap } from './discovery.js';

const server = (command: string, args: string[], extra: Partial<MCPServerEntry> = {}): MCPServerEntry =>
  ({ name: 's', command, args, transport: 'stdio', ...extra });

describe('launchTarget: node option values are not the entry', () => {
  it.each([
    [['-r', 'dotenv/config', '/srv/index.js']],
    [['--require', 'dotenv/config', '/srv/index.js']],
    [['--import', 'tsx', '/srv/index.js']],
    [['--env-file', '/srv/.env', '/srv/index.js']],
    [['--env-file=/srv/.env', '/srv/index.js']],
    [['--require=dotenv/config', '/srv/index.js']],
    [['--max-old-space-size', '4096', '/srv/index.js']],
    [['--experimental-strip-types', '--', '/srv/index.js']],
  ])('node %j', (args) => {
    expect(launchTarget(server('node', args)).entry).toBe(resolve('/srv/index.js'));
  });

  it('records local preload modules, not packages', () => {
    const t = launchTarget(server('node', ['-r', './setup.cjs', '--import', 'tsx', '--import=./hooks.mjs', 'index.js'], { cwd: '/srv' }));
    expect(t.entry).toBe(resolve('/srv/index.js'));
    expect(t.preloads).toEqual([resolve('/srv/setup.cjs'), resolve('/srv/hooks.mjs')]);
  });

  it('notes inline code', () => {
    const t = launchTarget(server('node', ['-e', 'require("./x")']));
    expect(t.entry).toBeUndefined();
    expect(t.note).toMatch(/inline/);
  });
});

describe('launchTarget: script runners', () => {
  it.each([
    ['tsx', ['/srv/src/index.ts']],
    ['tsx', ['watch', '/srv/src/index.ts']],
    ['npx', ['-y', 'tsx@4.19.2', '/srv/src/index.ts']],
    ['npx', ['tsx', '--tsconfig', 'tsconfig.json', '/srv/src/index.ts']],
    ['bun', ['run', '/srv/src/index.ts']],
    ['bun', ['/srv/src/index.ts']],
    ['deno', ['run', '-A', '--config', 'deno.json', '/srv/src/index.ts']],
  ])('%s %j', (cmd, args) => {
    expect(launchTarget(server(cmd, args)).entry).toBe(resolve('/srv/src/index.ts'));
  });

  it('fastmcp run / mcp run a Python file (object suffix dropped)', () => {
    expect(launchTarget(server('fastmcp', ['run', '/srv/server.py:app'])).entry).toBe(resolve('/srv/server.py'));
    expect(launchTarget(server('mcp', ['run', '/srv/server.py'])).entry).toBe(resolve('/srv/server.py'));
  });

  it('resolves relative entries against cwd', () => {
    expect(launchTarget(server('node', ['index.js'], { cwd: '/srv/app' })).entry).toBe(resolve('/srv/app/index.js'));
    expect(launchTarget(server('python3', ['-u', 'server.py'], { cwd: '/srv/py' })).entry).toBe(resolve('/srv/py/server.py'));
    expect(launchTarget(server('uv', ['run', 'server.py'], { cwd: '/srv/py' })).entry).toBe(resolve('/srv/py/server.py'));
  });

  it('a remote deno module is noted, a registry one is not local code', () => {
    expect(launchTarget(server('deno', ['run', 'https://example.com/mcp.ts'])).note).toMatch(/remote module/);
    expect(launchTarget(server('deno', ['run', 'npm:some-mcp'])).entry).toBeUndefined();
  });

  it('a package runner of a published package has no local entry', () => {
    expect(launchTarget(server('npx', ['-y', '@scope/mcp@1.0.0'])).entry).toBeUndefined();
  });

  it('package-manager scripts name the package directory', () => {
    expect(launchTarget(server('pnpm', ['--dir', '/srv/app', 'start']))).toMatchObject({ packageDir: resolve('/srv/app'), script: 'start' });
    expect(packageScriptRun(['--cwd', '/x', 'run', 'serve'])).toEqual({ dir: '/x', script: 'serve' });
    expect(packageScriptRun(['dlx', 'pkg'])).toBeUndefined();
  });
});

describe('parseServerMap keeps cwd', () => {
  it('reads a stdio server working directory', () => {
    const [s] = parseServerMap({ a: { command: 'node', args: ['index.js'], cwd: '/srv/app' } });
    expect(s.cwd).toBe('/srv/app');
  });
});

describe('resolveServerSources: launch targets on disk', () => {
  let dir: string;
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'vaso-launch-'));
    writeFileSync(join(dir, 'index.js'), 'import "./tools.js";\nconsole.log("entry");\n');
    writeFileSync(join(dir, 'tools.js'), 'export const t = 1;\n');
    writeFileSync(join(dir, 'setup.cjs'), 'require("child_process").execSync(process.argv[2]);\n');
    mkdirSync(join(dir, 'pkg', 'src'), { recursive: true });
    writeFileSync(join(dir, 'pkg', 'package.json'), JSON.stringify({ name: 'p', scripts: { start: 'node dist/index.js' } }));
    writeFileSync(join(dir, 'pkg', 'src', 'index.ts'), 'export const fromTs = true;\n');
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it('reads the entry past -r and includes a local preload', async () => {
    const [src] = await resolveServerSources([server('node', ['-r', join(dir, 'setup.cjs'), join(dir, 'index.js')])]);
    expect(src.sourceCode).toContain('console.log("entry")');
    expect(src.sourceCode).toContain('execSync');
    expect(src.unanalyzed).toBeUndefined();
  });

  it('notes a missing entry file instead of passing silently', async () => {
    const [src] = await resolveServerSources([server('node', [join(dir, 'gone.js')])]);
    expect(src.sourceCode).toBeUndefined();
    expect(src.unanalyzed).toMatch(/not found/);
    expect(src.readFailure).toBeUndefined();
  });

  it('follows a package script to the TypeScript source of an unbuilt checkout', async () => {
    const [src] = await resolveServerSources([server('pnpm', ['--dir', join(dir, 'pkg'), 'start'])]);
    expect(src.sourceCode).toContain('fromTs');
  });

  it('notes inline code', async () => {
    const [src] = await resolveServerSources([server('node', ['-e', 'console.log(1)'])]);
    expect(src.unanalyzed).toMatch(/inline/);
  });
});
