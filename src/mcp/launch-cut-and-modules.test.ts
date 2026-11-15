import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { launchTarget, resolveServerSources, uvRunModule } from './source-resolver.js';
import type { MCPServerEntry } from './types.js';

const EXEC_TOOL = 'const { exec } = require("child_process");\nserver.tool("run", {cmd: z.string()}, async ({cmd}) => { exec(cmd); return {content:[]}; });\n';
const PY_TOOL = 'import subprocess\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP("x")\n@mcp.tool()\ndef run(cmd: str) -> str:\n    return subprocess.run(cmd, shell=True)\n';

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'vaso-launch-')); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

function write(rel: string, content: string): string {
  const path = join(dir, rel);
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, content);
  return path;
}

const server = (command: string, args: string[] = [], cwd?: string): MCPServerEntry => ({ name: 's', command, args, transport: 'stdio', ...(cwd ? { cwd } : {}) });

function pkg(start: string): string {
  write('p/evil.js', EXEC_TOOL);
  write('p/package.json', JSON.stringify({ name: 'p', version: '1.0.0', scripts: { start } }));
  return join(dir, 'p');
}

describe('package scripts longer than the read cap', () => {
  it('a first command followed by padding is still read', async () => {
    const [source] = await resolveServerSources([server('npm', ['--prefix', pkg(`node evil.js${' '.repeat(60000)}`), 'start'])]);
    expect(source.sourceCode).toContain('exec(cmd)');
  });

  it('a command cut in its later arguments is read up to the cut', async () => {
    const [source] = await resolveServerSources([server('npm', ['--prefix', pkg(`node evil.js --label ${'x'.repeat(20000)}`), 'start'])]);
    expect(source.sourceCode).toContain('exec(cmd)');
  });

  it('a command cut inside a quoted argument is read up to the quote', async () => {
    const [source] = await resolveServerSources([server('npm', ['--prefix', pkg(`node evil.js "${'a b '.repeat(5000)}"`), 'start'])]);
    expect(source.sourceCode).toContain('exec(cmd)');
  });

  it('a resolving first command does not hide that the rest was not read', async () => {
    write('p/index.js', 'console.log("ok");\n');
    const [source] = await resolveServerSources([server('npm', ['--prefix', pkg(`node index.js${' '.repeat(9000)}&& node evil.js`), 'start'])]);
    expect(source.sourceCode).toContain('console.log');
    expect(source.readFailure).toMatch(/longer than 8 KiB/);
  });

  it('an entry word past the cap is not guessed: noted', async () => {
    const [source] = await resolveServerSources([server('npm', ['--prefix', pkg(`node${' '.repeat(60000)}evil.js`), 'start'])]);
    expect(source.sourceCode).toBeUndefined();
    expect(source.unanalyzed).toMatch(/longer than 8 KiB/);
  });
});

describe('every command of a package script chain', () => {
  it.each([
    ['&&', 'node index.js && node evil.js'],
    [';', 'node index.js; node evil.js'],
    ['||', 'node index.js || node evil.js'],
    ['a nested sh -c', `sh -c 'node index.js && node evil.js'`],
  ])('%s: the later command\'s file is analysed too', async (_label, start) => {
    write('p/index.js', 'console.log("ok");\n');
    const [source] = await resolveServerSources([server('npm', ['--prefix', pkg(start), 'start'])]);
    expect(source.sourceCode).toContain('console.log');
    expect(source.sourceCode).toContain('exec(cmd)');
    expect(source.readFailure).toBeUndefined();
  });

  it('a missing build output before a later command keeps the package entry', async () => {
    write('p/index.js', EXEC_TOOL);
    write('p/scripts/check.js', 'console.log("check");\n');
    write('p/package.json', JSON.stringify({ name: 'p', version: '1.0.0', main: 'index.js', scripts: { start: 'node dist/server.js && node scripts/check.js' } }));
    const [source] = await resolveServerSources([server('npm', ['--prefix', join(dir, 'p'), 'start'])]);
    expect(source.sourceCode).toContain('exec(cmd)');
    expect(source.sourceCode).toContain('console.log("check")');
  });

  it('more commands than the cap: read only in part', async () => {
    write('p/index.js', 'console.log("ok");\n');
    const start = ['node index.js', ...Array.from({ length: 20 }, () => 'true'), 'node evil.js'].join(' && ');
    const [source] = await resolveServerSources([server('npm', ['--prefix', pkg(start), 'start'])]);
    expect(source.sourceCode).not.toContain('exec(cmd)');
    expect(source.readFailure).toMatch(/more than 16 commands/);
  });

  it('a later command in another language is noted, not mixed in', async () => {
    write('p/index.js', 'console.log("ok");\n');
    write('p/tool.py', PY_TOOL);
    const [source] = await resolveServerSources([server('npm', ['--prefix', pkg('node index.js && python3 tool.py'), 'start'])]);
    expect(source.sourceCode).not.toContain('shell=True');
    expect(source.readFailure).toMatch(/another language/);
  });
});

describe('python -m and uv -m launches', () => {
  it('python -m without a working directory is noted', async () => {
    const [source] = await resolveServerSources([server('python3', ['-m', 'mymod'])]);
    expect(source.sourceCode).toBeUndefined();
    expect(source.unanalyzed).toMatch(/Python module mymod/);
  });

  it('python -m in a cwd without the module notes the installed module', async () => {
    const [source] = await resolveServerSources([server('python3', ['-m', 'mymod'], dir)]);
    expect(source.unanalyzed).toBe('runs the installed Python module mymod');
  });

  it.each([
    ['uv run --directory P python -m mod', (p: string) => ['run', '--directory', p, 'python', '-m', 'mymod']],
    ['uv --directory P run -m mod', (p: string) => ['--directory', p, 'run', '-m', 'mymod']],
    ['uv --directory P run --module mod', (p: string) => ['--directory', p, 'run', '--module', 'mymod']],
  ])('%s reads P/mod.py', async (_label, args) => {
    write('srv/mymod.py', PY_TOOL);
    const [source] = await resolveServerSources([server('uv', args(join(dir, 'srv')))]);
    expect(source.sourceCode).toContain('shell=True');
  });

  it('uv -m reads a package\'s __main__.py', async () => {
    write('srv/mymod/__main__.py', PY_TOOL);
    const [source] = await resolveServerSources([server('uv', ['--directory', join(dir, 'srv'), 'run', '-m', 'mymod'])]);
    expect(source.sourceCode).toContain('shell=True');
  });

  it('uvRunModule needs a known directory', () => {
    expect(uvRunModule(['run', '-m', 'm'])).toEqual({ module: 'm' });
    expect(uvRunModule(['--directory', 'rel', 'run', '-m', 'm'])).toEqual({ module: 'm' });
    expect(uvRunModule(['--directory', '/abs', 'run', '-m', 'm'])).toEqual({ module: 'm', directory: '/abs' });
    expect(uvRunModule(['run', 'server.py'])).toBeUndefined();
    expect(uvRunModule(['tool', 'run', 'x'])).toBeUndefined();
    expect(launchTarget(server('uv', ['run', 'python', '-m', 'm'], '/w'))).toEqual({ preloads: [], module: 'm', moduleBase: '/w' });
  });
});

describe('node preloads run before the entry', () => {
  it('a preload is analysed when the entry is missing', async () => {
    const preload = write('evil.js', EXEC_TOOL);
    const [source] = await resolveServerSources([server('node', ['-r', preload, join(dir, 'missing.js')])]);
    expect(source.sourceCode).toContain('exec(cmd)');
  });
});
