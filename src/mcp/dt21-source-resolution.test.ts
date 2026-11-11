import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolveServerSources, resolveSourcePaths } from './source-resolver.js';
import { shellLaunchTarget } from './shell-launch.js';
import { sourceReadResult } from '../core/engine.js';
import type { MCPServerEntry } from './types.js';

const SDK = 'const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");\n';
const EXEC_TOOL = 'const { exec } = require("child_process"); server.tool("run", {cmd: z.string()}, async ({cmd}) => { exec(cmd); return {content:[]}; });\n';
/** A thin Mach-O universal header (cafebabe + 2 archs) followed by padding. */
const MACHO = Buffer.concat([Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2]), Buffer.alloc(256)]);

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'vaso-dt21-src-')); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

function write(rel: string, content: string | Buffer, mode = 0o644): string {
  const path = join(dir, rel);
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, content);
  chmodSync(path, mode);
  return path;
}

const server = (command: string, args: string[] = []): MCPServerEntry => ({ name: 's', command, args, transport: 'stdio' });

describe('dt21 g3-F7: a flat Python script imports its siblings by name', () => {
  it('follows `from tools import x` and `import helpers` transitively, without __init__.py', async () => {
    const entry = write('srv/server.py', 'from mcp.server.fastmcp import FastMCP\nfrom tools import run_cmd\nimport json, helpers as h\n');
    write('srv/tools.py', 'import subprocess\nfrom deep import go\ndef run_cmd(cmd):\n    return subprocess.run(cmd, shell=True)\n');
    write('srv/deep.py', 'def go(): pass\n');
    write('srv/helpers/__init__.py', 'X = 1\n');
    write('srv/unrelated.py', 'import os\nos.system("never imported")\n');
    const [source] = await resolveServerSources([server('python3', [entry])]);
    expect(source.sourceCode).toContain('shell=True');
    expect(source.sourceCode).toContain('def go()');
    expect(source.sourceCode).toContain('X = 1');
    expect(source.sourceCode).not.toContain('never imported');

    const given = await resolveSourcePaths([entry]);
    expect(given.sources[0].sourceCode).toContain('shell=True');
  });

  it('a stdlib or installed module name with no sibling file is not followed', async () => {
    const entry = write('srv/server.py', 'import os\nfrom pathlib import Path\n');
    const [source] = await resolveServerSources([server('python3', [entry])]);
    expect(source.sourceCode).toBe('import os\nfrom pathlib import Path\n');
  });
});

describe('dt21 g3-F8: module following never drops files silently', () => {
  it('a configured server importing more than 200 modules is reported as read only in part', async () => {
    const lines = [SDK];
    for (let i = 0; i < 205; i++) {
      lines.push(`require('./m${String(i).padStart(3, '0')}.js');`);
      write(`many/m${String(i).padStart(3, '0')}.js`, i === 204 ? EXEC_TOOL : `module.exports = ${i};\n`);
    }
    const entry = write('many/index.js', lines.join('\n'));
    const [source] = await resolveServerSources([server('node', [entry])]);
    expect(source.readFailure).toMatch(/more than 200 source modules/);
    const result = sourceReadResult([source]);
    expect(result?.message).toContain('only in part');
  });

  it('--source on a checkout without an entry reads the files that use no SDK too', async () => {
    write('few/a.js', SDK + 'module.exports = 1;\n');
    write('few/zz.js', EXEC_TOOL);
    const { sources } = await resolveSourcePaths([join(dir, 'few')]);
    expect(sources[0].sourceCode).toContain('exec(cmd)');
  });

  it('--source sweeps tools loaded by a computed path also without an entry file', async () => {
    write('dyn/server.mjs', 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\nfor (const f of readdirSync(new URL("./tools", import.meta.url))) (await import(new URL("./tools/" + f, import.meta.url))).register(server);\n');
    write('dyn/tools/run.mjs', EXEC_TOOL);
    const { sources } = await resolveSourcePaths([join(dir, 'dyn')]);
    expect(sources[0].sourceCode).toContain('exec(cmd)');
  });

  it('--source on a checkout over the file limit reports the cut', async () => {
    for (let i = 0; i < 205; i++) write(`big/a${String(i).padStart(3, '0')}.js`, SDK);
    const { sources, unreadable } = await resolveSourcePaths([join(dir, 'big')]);
    expect(sources[0].readFailure).toMatch(/more than 200 source modules/);
    expect(unreadable.length).toBeGreaterThan(0);
  });
});

describe('dt21 g3-F9: --source on an unbuilt TypeScript checkout', () => {
  it('falls back to the TypeScript source when package.json main/bin are not built yet', async () => {
    write('ts1/package.json', JSON.stringify({ name: 'ts1-mcp', main: 'dist/index.js', bin: { ts1: 'dist/index.js' } }));
    write('ts1/src/index.ts', 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"; import "./tools/run.js";\n');
    write('ts1/src/tools/run.ts', EXEC_TOOL);
    const { sources, unreadable } = await resolveSourcePaths([join(dir, 'ts1')]);
    expect(unreadable).toEqual([]);
    expect(sources[0].sourceCode).toContain('exec(cmd)');
  });

  it('a main naming a directory resolves to its index.js, as in Node', async () => {
    write('m/package.json', JSON.stringify({ name: 'm', main: 'lib' }));
    write('m/lib/index.js', EXEC_TOOL);
    const [source] = await resolveServerSources([server('node', [join(dir, 'm')])]);
    expect(source.sourceCode).toContain('exec(cmd)');
  });
});

describe('dt21 g3-F10: src/ and dist/ of one module are read once', () => {
  it('an entry at the checkout root reads dist/ through its import and skips the src/ twin', async () => {
    write('dup/package.json', JSON.stringify({ name: 'dup-mcp', main: 'index.js' }));
    write('dup/index.js', 'require("./dist/index.js");\n');
    write('dup/dist/index.js', EXEC_TOOL);
    write('dup/src/index.ts', EXEC_TOOL);
    write('dup/src/extra.ts', 'export const extra = 1;\n');
    const { sources } = await resolveSourcePaths([join(dir, 'dup')]);
    const code = sources[0].sourceCode!;
    expect(code.split('exec(cmd)').length - 1).toBe(1);
    // a module with no build twin is still swept
    expect(code).toContain('extra = 1');
  });
});

describe('dt21 g3-F11: compiled binaries and shell launchers', () => {
  it('a Mach-O run directly is a compiled binary whatever its extension', async () => {
    const js = write('srv/server.js', MACHO, 0o755);
    const py = write('srv/server.py', MACHO, 0o755);
    const sources = await resolveServerSources([server(js), server(py)]);
    for (const s of sources) {
      expect(s.compiledBinary).toBe('Mach-O executable');
      expect(s.sourceCode).toBeUndefined();
    }
  });

  it('a .js run through node keeps its extension rule (Node reads it as source)', async () => {
    const js = write('srv/server.js', EXEC_TOOL);
    const [source] = await resolveServerSources([server('node', [js])]);
    expect(source.sourceCode).toContain('exec(cmd)');
  });

  it('a launcher script is followed to the file it starts', async () => {
    write('srv/real.js', EXEC_TOOL);
    const launcher = write('srv/launch.sh', '#!/bin/sh\nexec node "$(dirname "$0")/real.js" "$@"\n', 0o755);
    const [source] = await resolveServerSources([server(launcher)]);
    expect(source.sourceCode).toContain('exec(cmd)');
    expect(source.localPath).toBe(join(dir, 'srv/real.js'));
  });

  it('a launcher whose target is missing is reported, not passed silently', async () => {
    const launcher = write('srv/launch.sh', '#!/bin/sh\nexec node "$(dirname "$0")/gone.js"\n', 0o755);
    const [source] = await resolveServerSources([server(launcher)]);
    expect(source.readFailure).toMatch(/gone\.js.*started by launch\.sh/);
  });

  it.each([
    ['exec node "$(dirname "$0")/real.js"', 'real.js'],
    ['exec node $(dirname $0)/real.js "$@"', 'real.js'],
    ['DIR="$(cd "$(dirname "$0")" && pwd)"\nexec /usr/local/bin/node --enable-source-maps "$DIR/dist/index.js"', 'dist/index.js'],
    ['SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")\npython3 -u ${SCRIPT_DIR}/server.py', 'server.py'],
    ['exec /usr/bin/env node ./real.mjs', 'real.mjs'],
    ['exec node /opt/srv/main.js', '/opt/srv/main.js'],
  ])('shellLaunchTarget(%j) → %s', (body, want) => {
    const launcher = join(dir, 'srv/launch.sh');
    const target = shellLaunchTarget(launcher, `#!/bin/bash\nset -e\n${body}\n`);
    expect(target).toBe(want.startsWith('/') ? want : join(dir, 'srv', want));
  });

  it.each([
    'exec node -e "require(1)"',
    'exec docker run --rm image',
    '# exec node real.js',
    'exec node "$SOMEWHERE/real.js"',
  ])('shellLaunchTarget(%j) → none', (body) => {
    expect(shellLaunchTarget(join(dir, 'launch.sh'), `#!/bin/sh\n${body}\n`)).toBeUndefined();
  });

  it('a non-shell file is never read as a launcher', () => {
    expect(shellLaunchTarget(join(dir, 'x.js'), 'exec node real.js\n')).toBeUndefined();
  });
});

describe('dt21 g3-R1: --source analyses every declared entry', () => {
  it('a bin that differs from main is analysed too (npx runs the bin)', async () => {
    write('b/package.json', JSON.stringify({ name: 'b-mcp', main: 'src/index.ts', bin: { b: 'dist/index.js' } }));
    write('b/src/index.ts', SDK + 'export const clean = 1;\n');
    write('b/dist/index.js', EXEC_TOOL);
    const { sources } = await resolveSourcePaths([join(dir, 'b')]);
    expect(sources[0].sourceCode).toContain('clean = 1');
    expect(sources[0].sourceCode).toContain('exec(cmd)');
  });
});
