import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { inferPackageName, resolveLocalPath, resolveServerSources } from './source-resolver.js';
import type { MCPServerEntry } from './types.js';

function makeServer(overrides?: Partial<MCPServerEntry>): MCPServerEntry {
  return {
    name: 'test-server',
    transport: 'stdio',
    ...overrides,
  };
}

describe('inferPackageName', () => {
  it('returns package name for npx command', () => {
    expect(inferPackageName(makeServer({ command: 'npx', args: ['@modelcontextprotocol/server-fs'] })))
      .toBe('@modelcontextprotocol/server-fs');
  });

  it('returns package name for npx with -y flag', () => {
    expect(inferPackageName(makeServer({ command: 'npx', args: ['-y', 'mcp-server-fetch'] })))
      .toBe('mcp-server-fetch');
  });

  it('returns package name for uvx command', () => {
    expect(inferPackageName(makeServer({ command: 'uvx', args: ['mcp-server-git'] })))
      .toBe('mcp-server-git');
  });

  it('returns package name for uvx with run keyword', () => {
    expect(inferPackageName(makeServer({ command: 'uv', args: ['run', 'mcp-server-sqlite'] })))
      .toBe('mcp-server-sqlite');
  });

  it('returns undefined for node command', () => {
    expect(inferPackageName(makeServer({ command: 'node', args: ['/path/to/server.js'] })))
      .toBeUndefined();
  });

  it('returns undefined when no args', () => {
    expect(inferPackageName(makeServer({ command: 'npx' })))
      .toBeUndefined();
  });

  it('returns undefined for unknown command', () => {
    expect(inferPackageName(makeServer({ command: 'python', args: ['server.py'] })))
      .toBeUndefined();
  });
});

describe('resolveLocalPath', () => {
  it('resolves node /path/to/file.js', () => {
    const result = resolveLocalPath(makeServer({ command: 'node', args: ['/path/to/server.js'] }));
    expect(result).toBe('/path/to/server.js');
  });

  it('resolves relative path with node', () => {
    const result = resolveLocalPath(makeServer({ command: 'node', args: ['./local/server.js'] }));
    expect(result).toBe(resolve('./local/server.js'));
  });

  it('resolves absolute direct path', () => {
    const result = resolveLocalPath(makeServer({ command: '/usr/local/bin/my-server', args: ['--port', '3000'] }));
    expect(result).toBe('/usr/local/bin/my-server');
  });

  it('resolves relative direct path with ./', () => {
    const result = resolveLocalPath(makeServer({ command: './my-server', args: ['--port', '3000'] }));
    expect(result).toBe(resolve('./my-server'));
  });

  it('returns undefined for npx command', () => {
    expect(resolveLocalPath(makeServer({ command: 'npx', args: ['some-pkg'] }))).toBeUndefined();
  });

  it('returns undefined when no args for node', () => {
    expect(resolveLocalPath(makeServer({ command: 'node' }))).toBeUndefined();
  });
});

describe('resolveServerSources', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('sets packageName for npx server', async () => {
    const servers = [makeServer({ command: 'npx', args: ['-y', '@mcp/server-fs'] })];
    const sources = await resolveServerSources(servers);
    expect(sources).toHaveLength(1);
    expect(sources[0].packageName).toBe('@mcp/server-fs');
    expect(sources[0].localPath).toBeUndefined();
  });

  it('returns serverName in result', async () => {
    const servers = [makeServer({ name: 'my-mcp-server', command: 'npx', args: ['pkg'] })];
    const sources = await resolveServerSources(servers);
    expect(sources[0].serverName).toBe('my-mcp-server');
  });

  it('handles empty server list', async () => {
    const sources = await resolveServerSources([]);
    expect(sources).toEqual([]);
  });

  it('sets localPath for node command', async () => {
    const servers = [makeServer({ command: 'node', args: ['/tmp/server.js'] })];
    const sources = await resolveServerSources(servers);
    expect(sources).toHaveLength(1);
    expect(sources[0].localPath).toBe('/tmp/server.js');
    expect(sources[0].packageName).toBeUndefined();
  });

  it('handles multiple servers', async () => {
    const servers = [
      makeServer({ name: 'srv1', command: 'npx', args: ['pkg1'] }),
      makeServer({ name: 'srv2', command: 'npx', args: ['pkg2'] }),
    ];
    const sources = await resolveServerSources(servers);
    expect(sources).toHaveLength(2);
    expect(sources[0].packageName).toBe('pkg1');
    expect(sources[1].packageName).toBe('pkg2');
  });

  describe('package resolution (opt-in)', () => {
    it('does not resolve npm packages unless resolvePackages is set', async () => {
      const npmFetcher = vi.fn(async () => 'SHOULD NOT BE CALLED');
      const servers = [makeServer({ command: 'npx', args: ['-y', '@mcp/server-fs'] })];
      const sources = await resolveServerSources(servers, { npmFetcher });
      expect(npmFetcher).not.toHaveBeenCalled();
      expect(sources[0].sourceCode).toBeUndefined();
    });

    it('resolves npm-packaged servers when resolvePackages is set', async () => {
      const npmFetcher = vi.fn(async () => 'RESOLVED SOURCE');
      const servers = [makeServer({ command: 'npx', args: ['-y', '@mcp/server-fs'] })];
      const sources = await resolveServerSources(servers, { resolvePackages: true, npmFetcher });
      expect(npmFetcher).toHaveBeenCalledWith('@mcp/server-fs');
      expect(sources[0].sourceCode).toBe('RESOLVED SOURCE');
    });

    it('does not resolve uvx/PyPI packages (analyzers are JS-only)', async () => {
      const npmFetcher = vi.fn(async () => 'X');
      const servers = [makeServer({ command: 'uvx', args: ['some-python-mcp'] })];
      const sources = await resolveServerSources(servers, { resolvePackages: true, npmFetcher });
      expect(npmFetcher).not.toHaveBeenCalled();
      expect(sources[0].packageName).toBe('some-python-mcp');
      expect(sources[0].sourceCode).toBeUndefined();
    });

    it('does not resolve local (node) servers via the fetcher', async () => {
      const npmFetcher = vi.fn(async () => 'X');
      const servers = [makeServer({ command: 'node', args: ['/tmp/does-not-exist.js'] })];
      await resolveServerSources(servers, { resolvePackages: true, npmFetcher });
      expect(npmFetcher).not.toHaveBeenCalled();
    });
  });
});

describe('Python and absolute-interpreter servers', () => {
  it('resolves python/python3/py scripts, skipping options and their values', () => {
    expect(resolveLocalPath(makeServer({ command: 'python3', args: ['/srv/server.py', '/ws'] }))).toBe(resolve('/srv/server.py'));
    expect(resolveLocalPath(makeServer({ command: 'python', args: ['-u', '-X', 'utf8', '/srv/server.py'] }))).toBe(resolve('/srv/server.py'));
    expect(resolveLocalPath(makeServer({ command: 'py', args: ['C:/mcp/server.py'] }))).toBe(resolve('C:/mcp/server.py'));
  });

  it('resolves the script, not the interpreter, when the interpreter is a path', () => {
    expect(resolveLocalPath(makeServer({ command: '/home/u/.venv/bin/python3.12', args: ['/srv/server.py'] })))
      .toBe(resolve('/srv/server.py'));
    expect(resolveLocalPath(makeServer({ command: '/home/u/.nvm/versions/node/v22.1.0/bin/node', args: ['/srv/index.js'] })))
      .toBe(resolve('/srv/index.js'));
  });

  it('has no file for python -m / -c', () => {
    expect(resolveLocalPath(makeServer({ command: 'python3', args: ['-m', 'mcp_server_git'] }))).toBeUndefined();
    expect(resolveLocalPath(makeServer({ command: 'python3', args: ['-c', 'print(1)'] }))).toBeUndefined();
  });

  it('resolves uv run scripts against --directory (MCP quickstart form)', () => {
    expect(resolveLocalPath(makeServer({ command: 'uv', args: ['--directory', '/srv/weather', 'run', 'weather.py'] })))
      .toBe(resolve('/srv/weather/weather.py'));
    expect(resolveLocalPath(makeServer({ command: 'uv', args: ['run', '--with', 'mcp[cli]', 'mcp', 'run', '/srv/server.py'] })))
      .toBe(resolve('/srv/server.py'));
    expect(resolveLocalPath(makeServer({ command: 'uv', args: ['run', 'mcp-server-sqlite'] }))).toBeUndefined();
  });

  it('does not report a uv run script or its --directory as a package', () => {
    expect(inferPackageName(makeServer({ command: 'uv', args: ['--directory', '/srv/weather', 'run', 'weather.py'] })))
      .toBeUndefined();
    expect(inferPackageName(makeServer({ command: 'uv', args: ['--directory', '/srv/x', 'run', 'mcp-server-x'] })))
      .toBe('mcp-server-x');
  });

  describe('language tagging', () => {
    let dir: string;
    beforeEach(() => {
      dir = mkdtempSync(join(tmpdir(), 'vaso-src-'));
      return () => rmSync(dir, { recursive: true, force: true });
    });

    it('tags python scripts and leaves JavaScript untagged', async () => {
      writeFileSync(join(dir, 'server.py'), 'import os\n');
      writeFileSync(join(dir, 'index.js'), 'console.log(1)\n');
      writeFileSync(join(dir, 'tool'), '#!/usr/bin/env python3\nprint(1)\n');
      const sources = await resolveServerSources([
        makeServer({ name: 'py', command: '/opt/venv/bin/python', args: [join(dir, 'server.py')] }),
        makeServer({ name: 'uv', command: 'uv', args: ['--directory', dir, 'run', 'server.py'] }),
        makeServer({ name: 'js', command: 'node', args: [join(dir, 'index.js')] }),
        makeServer({ name: 'shebang', command: join(dir, 'tool') }),
      ]);
      expect(sources.map((s) => [s.serverName, s.language, Boolean(s.sourceCode)])).toEqual([
        ['py', 'python', true],
        ['uv', 'python', true],
        ['js', undefined, true],
        ['shebang', 'python', true],
      ]);
    });

    it('runs a Python package directory through its __main__.py', async () => {
      mkdirSync(join(dir, 'pkg'));
      writeFileSync(join(dir, 'pkg', '__main__.py'), 'print("hi")\n');
      const [source] = await resolveServerSources([
        makeServer({ command: 'python3', args: [join(dir, 'pkg')] }),
      ]);
      expect(source.sourceCode).toContain('print("hi")');
      expect(source.language).toBe('python');
    });
  });
});
