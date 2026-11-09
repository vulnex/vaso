import { describe, it, expect, beforeEach } from 'vitest';
import { chmodSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MAX_SERVER_SOURCE_BYTES, resolveServerSources, resolveSourcePaths } from './source-resolver.js';
import type { MCPServerEntry } from './types.js';
import { sourceReadResult } from '../core/engine.js';
import { mcp001 } from '../checks/mcp/mcp-001-config-discovery.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';

const node = (name: string, file: string): MCPServerEntry => ({ name, transport: 'stdio', command: 'node', args: [file] });
const EXEC_TOOL = 'const { exec } = require("child_process"); server.tool("run", {cmd: z.string()}, async ({cmd}) => { exec(cmd); });';
const isRoot = process.getuid?.() === 0;

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'vaso-mods-'));
  return () => {
    rmSync(dir, { recursive: true, force: true });
  };
});

function write(rel: string, content: string | Buffer): string {
  const path = join(dir, rel);
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, content);
  return path;
}

describe('dt20 g3-F7: a local JS server is read with the modules it imports', () => {
  it('follows relative imports and requires, transitively, with file markers', async () => {
    const entry = write('srv/index.js', 'import { tool } from "./tools/run.js"; const h = require("./lib/helper"); server.tool("x", {}, async () => ({content:[]}));');
    write('srv/tools/run.js', `${EXEC_TOOL}\nexport * from "../util/index.js";`);
    write('srv/lib/helper.js', 'module.exports = {};');
    write('srv/util/index.js', 'export const u = 1;');
    write('srv/node_modules/x/index.js', 'exec(cmd)');
    write('srv/unrelated.js', 'should not be read');
    const [source] = await resolveServerSources([node('s', entry)]);
    expect(source.sourceCode).toContain('// === tools/run.js ===');
    expect(source.sourceCode).toContain('// === lib/helper.js ===');
    expect(source.sourceCode).toContain('// === util/index.js ===');
    expect(source.sourceCode).not.toContain('should not be read');
    expect(source.sourceRoot).toBe(join(dir, 'srv'));
    expect(source.readFailure).toBeUndefined();
  });

  it('resolves a TypeScript `./x.js` import to x.ts and a directory to its index', async () => {
    const entry = write('ts/src/index.ts', 'import { run } from "./run.js"; import "./tools";');
    write('ts/src/run.ts', EXEC_TOOL);
    write('ts/src/tools/index.ts', 'export const t = 1;');
    const [source] = await resolveServerSources([node('s', entry)]);
    expect(source.sourceCode).toContain('// === run.ts ===');
    expect(source.sourceCode).toContain('// === tools/index.ts ===');
  });

  it('stays inside the server directory (the package.json root)', async () => {
    write('outside/secret.js', 'outside code');
    write('pkg/package.json', '{"name":"pkg"}');
    const entry = write('pkg/dist/index.js', 'require("../lib/a.js"); require("../../outside/secret.js"); require("../node_modules/dep/x.js");');
    write('pkg/lib/a.js', 'a module');
    write('pkg/node_modules/dep/x.js', 'vendored');
    const [source] = await resolveServerSources([node('s', entry)]);
    expect(source.sourceCode).toContain('a module');
    expect(source.sourceCode).not.toContain('outside code');
    expect(source.sourceCode).not.toContain('vendored');
    expect(source.sourceRoot).toBe(join(dir, 'pkg'));
  });

  it('a single-file server keeps its plain source', async () => {
    const entry = write('one/s.js', `${EXEC_TOOL} require("fs");`);
    const [source] = await resolveServerSources([node('s', entry)]);
    expect(source.sourceCode).toBe(`${EXEC_TOOL} require("fs");`);
    expect(source.sourceRoot).toBeUndefined();
  });

  it.skipIf(isRoot)('an unreadable helper module is reported (SOURCE-READ), the rest analyzed', async () => {
    const entry = write('f/index.js', 'const h = require("./lib/helper.js"); server.tool("x", {}, async () => h.go());');
    const helper = write('f/lib/helper.js', EXEC_TOOL);
    chmodSync(helper, 0o000);
    try {
      const sources = await resolveServerSources([node('f', entry)]);
      expect(sources[0].sourceCode).toContain('server.tool("x"');
      expect(sources[0].readFailure).toMatch(/EACCES|permission/i);
      const result = sourceReadResult(sources);
      expect(result?.errored).toBe(true);
      expect(result?.message).toContain('could not be read (1 only in part)');
    } finally {
      chmodSync(helper, 0o644);
    }
  });

  it.skipIf(isRoot)('a module in a directory that cannot be traversed is reported (SOURCE-READ)', async () => {
    const entry = write('f2/index.js', 'const h = require("./lib/helper.js"); server.tool("x", {}, async () => h.go());');
    write('f2/lib/helper.js', EXEC_TOOL);
    chmodSync(join(dir, 'f2/lib'), 0o000);
    try {
      const sources = await resolveServerSources([node('f2', entry)]);
      expect(sources[0].sourceCode).toContain('server.tool("x"');
      expect(sources[0].readFailure).toMatch(/EACCES|permission/i);
      expect(sourceReadResult(sources)?.errored).toBe(true);
      // --source too, for an imported module and for an unlisted directory
      const viaSource = await resolveSourcePaths([join(dir, 'f2')]);
      expect(viaSource.sources[0].readFailure).toMatch(/EACCES|permission/i);
      expect(viaSource.unreadable.length).toBeGreaterThan(0);
    } finally {
      chmodSync(join(dir, 'f2/lib'), 0o755);
    }
  });

  it('a missing module is no failure', async () => {
    const entry = write('f3/index.js', 'require("./nope.js"); import("./also-missing");');
    const [source] = await resolveServerSources([node('f3', entry)]);
    expect(source.readFailure).toBeUndefined();
  });

  it('caps the total source per server and reports what was skipped', async () => {
    const big = `var a = "${'x'.repeat(Math.floor(MAX_SERVER_SOURCE_BYTES / 3) + 1024)}";\n`;
    const entry = write('m/index.js', `require("./t1.js"); require("./t2.js"); require("./t3.js");\n${big}`);
    for (const n of ['t1', 't2', 't3']) write(`m/${n}.js`, big);
    const sources = await resolveServerSources([node('m', entry)]);
    // entry + one module fit; the other two are skipped
    expect(sources[0].sourceCode).toContain('// === t1.js ===');
    expect(sources[0].sourceCode).not.toContain('// === t2.js ===');
    expect(sources[0].readFailure).toMatch(/total analysis limit.*and 1 more module/);
  });

  it('a local Python entry in a package gets its sibling modules', async () => {
    write('py/pkg/__init__.py', '');
    const entry = write('py/pkg/server.py', 'from .tools import run\nfrom mcp.server.fastmcp import FastMCP\n');
    write('py/pkg/tools.py', 'import subprocess\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n');
    const [source] = await resolveServerSources([{ name: 'p', transport: 'stdio', command: 'python3', args: [entry] }]);
    expect(source.language).toBe('python');
    expect(source.sourceCode).toContain('subprocess.run(cmd, shell=True)');
  });
});

describe('dt20 g3-F7: --source <dir>', () => {
  it('the import scan stays linear on long whitespace runs', async () => {
    const entry = write('ws/index.js', `import${' '.repeat(200_000)}x; require${' '.repeat(200_000)}(y);`);
    const start = Date.now();
    await resolveServerSources([node('w', entry)]);
    expect(Date.now() - start).toBeLessThan(2000);
  });

  it('reads the modules the entry imports (s1)', async () => {
    write('s1/index.js', 'import { tool } from "./tools/run.js"; server.tool("x", {}, async () => ({content:[]}));');
    write('s1/tools/run.js', EXEC_TOOL);
    const { sources, unreadable } = await resolveSourcePaths([join(dir, 's1')]);
    expect(unreadable).toEqual([]);
    expect(sources[0].sourceCode).toContain('exec(cmd)');
    expect(sources[0].sourceRoot).toBe(join(dir, 's1'));
  });

  it('a checkout with an entry also gets its files the entry does not import (s3)', async () => {
    write('s3/package.json', '{"name":"s3","main":"src/index.js"}');
    write('s3/src/index.js', 'server.tool("x", {}, async () => ({content:[]}));');
    write('s3/src/tools/run.js', EXEC_TOOL);
    write('s3/src/tools/run.test.js', 'test fixture code');
    write('s3/vitest.config.ts', 'tool config');
    write('s3/dist/index.js', 'compiled copy');
    const { sources } = await resolveSourcePaths([join(dir, 's3')]);
    expect(sources[0].sourceCode).toMatch(/^\/\/ === src\/index\.js ===/);
    expect(sources[0].sourceCode).toContain('// === src/tools/run.js ===');
    expect(sources[0].sourceCode).not.toContain('test fixture code');
    expect(sources[0].sourceCode).not.toContain('tool config');
    expect(sources[0].sourceCode).not.toContain('compiled copy');
  });

  it('a checkout with no top-level entry is walked into subdirectories (s4)', async () => {
    write('s4/src/tools/run.js', EXEC_TOOL);
    write('s4/test/t.js', 'test code');
    const { sources, unreadable } = await resolveSourcePaths([join(dir, 's4')]);
    expect(unreadable).toEqual([]);
    expect(sources[0].sourceCode).toContain('exec(cmd)');
    expect(sources[0].sourceCode).not.toContain('test code');
  });

  it('an SDK-using file found by the walk brings its imports along', async () => {
    write('s5/src/server.js', 'import { Server } from "@modelcontextprotocol/sdk/server/index.js"; import "./tools/run.js";');
    write('s5/src/tools/run.js', EXEC_TOOL);
    write('s5/scripts/build.js', 'build script');
    const { sources } = await resolveSourcePaths([join(dir, 's5')]);
    expect(sources[0].sourceCode).toContain('exec(cmd)');
    expect(sources[0].sourceCode).not.toContain('build script');
  });

  it('four large files: the total cap skips the rest and lists them as unreadable', async () => {
    const big = `var a = "${'x'.repeat(Math.floor(MAX_SERVER_SOURCE_BYTES / 3) + 1024)}";\n`;
    for (const n of ['t0', 't1', 't2', 't3']) write(`multi/${n}.js`, big);
    const { sources, unreadable } = await resolveSourcePaths([join(dir, 'multi')]);
    expect(sources).toHaveLength(1);
    expect(unreadable).toEqual([join(dir, 'multi/t2.js'), join(dir, 'multi/t3.js')]);
    // …and the report carries them (SOURCE-READ)
    expect(sources[0].readFailure).toMatch(/total analysis limit.*and 1 more module/);
    expect(sourceReadResult(sources)?.errored).toBe(true);
  });
});

describe('dt20 decision 3: a compiled server binary is an inventory note', () => {
  const machO = Buffer.concat([Buffer.from([0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01]), Buffer.alloc(64)]);
  const elf = Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]), Buffer.alloc(64)]);

  it('records the format, no read failure (exit unchanged)', async () => {
    const bin = write('bin/github-mcp-server', machO);
    const sources = await resolveServerSources([{ name: 'gh', transport: 'stdio', command: bin, args: ['stdio'] }]);
    expect(sources[0].compiledBinary).toBe('Mach-O executable');
    expect(sources[0].sourceCode).toBeUndefined();
    expect(sources[0].readFailure).toBeUndefined();
    expect(sourceReadResult(sources)).toBeUndefined();
  });

  it('a binary over the content-scan limit is still a binary, not unreadable source', async () => {
    const bin = write('bin/big-server', Buffer.concat([elf, Buffer.alloc(6 * 1024 * 1024)]));
    const sources = await resolveServerSources([{ name: 'big', transport: 'stdio', command: bin, args: [] }]);
    expect(sources[0].compiledBinary).toBe('ELF executable');
    expect(sources[0].readFailure).toBeUndefined();
  });

  it('a script stays source whatever its first bytes', async () => {
    const script = write('bin/srv.js', Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]), Buffer.from(`\n${EXEC_TOOL}`)]));
    const [source] = await resolveServerSources([node('s', script)]);
    expect(source.compiledBinary).toBeUndefined();
    expect(source.sourceCode).toContain('exec(cmd)');
  });

  it.each([
    ['/usr/bin/env', ['npx', '-y', 'x']],
    ['/bin/bash', ['-c', 'npx -y x']],
    ['/usr/local/bin/docker', ['run', '-i', 'img']],
    ['/usr/bin/caffeinate', ['-i', 'npx', 'x']],
    ['/opt/homebrew/bin/uvx', ['x']],
    ['/usr/bin/nohup', ['node', 's.js']],
  ])('a launcher given by path (%s) is not the server binary', async (command, args) => {
    const [source] = await resolveServerSources([{ name: 'l', transport: 'stdio', command, args }]);
    expect(source.compiledBinary).toBeUndefined();
    expect(source.localPath).toBeUndefined();
  });

  it('--source given a binary reports it instead of failing', async () => {
    const bin = write('bin/rust-server', elf);
    const { sources, unreadable } = await resolveSourcePaths([bin]);
    expect(unreadable).toEqual([]);
    expect(sources[0].compiledBinary).toBe('ELF executable');
  });

  it('MCP-001 reports it as an info finding', async () => {
    const bin = write('bin/github-mcp-server', machO);
    const sources = await resolveServerSources([{ name: 'gh', transport: 'stdio', command: bin, args: ['stdio'] }]);
    const result = await mcp001.run({
      installation: { agent: 'mcp', installDir: dir, configFiles: [] },
      configs: [],
      platform: 'darwin',
      fs: new LocalFSProvider(),
      mcpConfigs: [{ source: 'x', filePath: join(dir, 'mcp.json'), servers: [{ name: 'gh', transport: 'stdio', command: bin, args: ['stdio'] }] }],
      mcpServerSources: sources,
    });
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('info');
    expect(result.message).toContain('1 run a compiled binary — source not analysed');
    expect(result.evidence?.some((e) => e.file === bin && e.detail === 'compiled binary (Mach-O executable) — source not analysed')).toBe(true);
  });
});
