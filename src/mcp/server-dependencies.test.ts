import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { collectServerDependencies } from './server-dependencies.js';

const fs = new LocalFSProvider();
let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'vaso-deps-'));
  return () => rmSync(dir, { recursive: true, force: true });
});

const write = (rel: string, content: string) => {
  const path = join(dir, rel);
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, content);
};

describe('collectServerDependencies — npm', () => {
  it('prefers the installed copy, then the lockfile, then the declared range', async () => {
    write('package.json', JSON.stringify({
      dependencies: { '@modelcontextprotocol/sdk': '^1.0.4', zod: '^3.0.0', express: '4.17.1' },
      devDependencies: { vitest: '^1.0.0' },
    }));
    write('node_modules/@modelcontextprotocol/sdk/package.json', JSON.stringify({ version: '1.20.2' }));
    write('package-lock.json', JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/zod': { version: '3.22.4' } } }));
    write('build/index.js', '');

    const deps = await collectServerDependencies(join(dir, 'build', 'index.js'), 'javascript', fs);
    expect(deps).toEqual([
      { name: '@modelcontextprotocol/sdk', ecosystem: 'npm', version: '1.20.2', source: join(dir, 'node_modules/@modelcontextprotocol/sdk/package.json') },
      { name: 'zod', ecosystem: 'npm', version: '3.22.4', source: join(dir, 'package-lock.json') },
      { name: 'express', ecosystem: 'npm', version: '4.17.1', source: join(dir, 'package.json') },
    ]);
  });

  it('keeps a declared range when nothing is locked', async () => {
    write('package.json', JSON.stringify({ dependencies: { '@modelcontextprotocol/sdk': '^0.5.0' } }));
    write('index.js', '');
    const deps = await collectServerDependencies(join(dir, 'index.js'), 'javascript', fs);
    expect(deps).toEqual([{ name: '@modelcontextprotocol/sdk', ecosystem: 'npm', range: '^0.5.0', source: join(dir, 'package.json') }]);
  });

  it('stays in the given directory when asked (resolved packages in the cache)', async () => {
    write('package.json', JSON.stringify({ dependencies: { leftpad: '1.0.0' } }));
    write('pkg/index.js', '');
    expect(await collectServerDependencies(join(dir, 'pkg', 'index.js'), 'javascript', fs, { searchParents: false })).toEqual([]);
  });
});

describe('collectServerDependencies — Python', () => {
  it('reads requirements and pins from uv.lock', async () => {
    write('requirements.txt', 'mcp[cli]>=1.2 ; python_version >= "3.10"\nhttpx==0.27.0\n# comment\n-r base.txt\n');
    write('uv.lock', '[[package]]\nname = "mcp"\nversion = "1.9.1"\n');
    write('server.py', '');
    const deps = await collectServerDependencies(join(dir, 'server.py'), 'python', fs);
    expect(deps).toEqual([
      { name: 'mcp', ecosystem: 'pypi', version: '1.9.1', source: join(dir, 'uv.lock') },
      { name: 'httpx', ecosystem: 'pypi', version: '0.27.0', source: join(dir, 'requirements.txt') },
    ]);
  });

  it('reads pyproject dependencies and an installed virtualenv', async () => {
    write('pyproject.toml', '[project]\nname = "weather"\ndependencies = ["mcp>=1.0,<1.9", "Requests~=2.31"]\n');
    write('.venv/lib/python3.12/site-packages/mcp-1.8.0.dist-info/METADATA', '');
    write('weather.py', '');
    const deps = await collectServerDependencies(join(dir, 'weather.py'), 'python', fs);
    expect(deps).toEqual([
      expect.objectContaining({ name: 'mcp', version: '1.8.0' }),
      { name: 'requests', ecosystem: 'pypi', range: '~=2.31', source: join(dir, 'pyproject.toml') },
    ]);
  });

  it('converts Poetry caret ranges', async () => {
    write('pyproject.toml', '[tool.poetry.dependencies]\npython = "^3.10"\nmcp = "^1.2"\n');
    write('main.py', '');
    const deps = await collectServerDependencies(join(dir, 'main.py'), 'python', fs);
    expect(deps).toEqual([{ name: 'mcp', ecosystem: 'pypi', range: '>=1.2.0,<2.0.0', source: join(dir, 'pyproject.toml') }]);
  });
});
