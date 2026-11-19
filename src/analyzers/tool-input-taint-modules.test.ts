import { describe, it, expect } from 'vitest';
import { MAX_GROUP_SOURCE, findTaintedSinks } from './tool-input-taint.js';
import type { MCPServerSource, ScanContext } from '../core/types.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { mcp004 } from '../checks/mcp/mcp-004-overprivileged-tools.js';
import { mcp005 } from '../checks/mcp/mcp-005-tool-injection.js';

/** Files joined the way the source resolver joins a server's modules. */
const joined = (files: Record<string, string>): string =>
  Object.entries(files).map(([path, code]) => `// === ${path} ===\n${code}`).join('\n\n');

const HELPERS = `import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
export function readData(name) {
  return fs.readFileSync(path.join('/data', name), 'utf8');
}
export function runIt(c) {
  return execSync(c);
}`;

const SERVER = `import { readData, runIt } from './helpers.js';
server.tool('read', { name: z.string() }, async ({ name }) => readData(name));
server.tool('run', { cmd: z.string() }, async ({ cmd }) => runIt(cmd));`;

let n = 0;
const ctx = (sourceCode: string): ScanContext => ({
  installation: { agent: 'mcp', installDir: '/tmp', configFiles: [] },
  configs: [], platform: 'darwin', fs: new LocalFSProvider(),
  mcpServerSources: [{ serverName: `m${++n}`, sourceCode, localPath: `/tmp/modules-${n}.js` } as MCPServerSource],
} as ScanContext);

describe('findTaintedSinks across modules', () => {
  it('follows tool input into helpers a server imports by name (the fix-brief repro)', () => {
    const code = joined({ 'dist/index.js': SERVER, 'dist/helpers.js': HELPERS });
    const sinks = findTaintedSinks(code, 'repro.js');
    expect(sinks).toEqual([
      expect.objectContaining({ kind: 'file-read', sink: 'fs.readFileSync', origin: 'name ← caller' }),
      expect.objectContaining({ kind: 'process', sink: 'execSync', origin: 'c ← caller' }),
    ]);
    // Lines point into the helpers file of the joined source
    const lines = code.split('\n');
    expect(lines[sinks[0].line - 1]).toContain('readFileSync');
    expect(lines[sinks[1].line - 1]).toContain('execSync(c)');
  });

  it('reports the repro through MCP-005 and tiers the exec as tainted in MCP-004', async () => {
    const code = joined({ 'dist/index.js': SERVER, 'dist/helpers.js': HELPERS });
    const r5 = await mcp005.run(ctx(code));
    expect(r5.passed).toBe(false);
    expect(r5.evidence?.map((e) => e.detail).join('\n')).toMatch(/readFileSync\(\) reads a path taken from tool input/);
    const r4 = await mcp004.run(ctx(code));
    const exec = r4.evidence?.find((e) => /execSync/.test(e.snippet ?? ''));
    expect(exec).toBeDefined();
    expect(exec!.detail).not.toMatch(/no tool input was traced/);
    expect(r4.severity).toBe('critical');
  });

  it('does not link modules that do not import each other', () => {
    const code = joined({
      'dist/index.js': `server.tool('run', {}, async ({ cmd }) => runIt(cmd));`,
      'dist/helpers.js': HELPERS,
    });
    expect(findTaintedSinks(code, 'unlinked.js')).toEqual([]);
  });

  it('does not report a helper called only with constants', () => {
    const code = joined({
      'dist/index.js': `import { runIt } from './helpers.js';\nserver.tool('v', {}, async () => runIt('git --version'));`,
      'dist/helpers.js': HELPERS,
    });
    expect(findTaintedSinks(code, 'const.js')).toEqual([]);
  });

  it('follows default and aliased imports', () => {
    const code = joined({
      'src/index.ts': `import run from './run';\nimport { readData as load } from './helpers';
server.tool('a', {}, async ({ cmd }) => run(cmd));
server.tool('b', {}, async ({ f }) => load(f));`,
      'src/run.ts': `import { exec } from 'child_process';\nexport default function run(command: string) { exec(command); }`,
      'src/helpers.ts': HELPERS,
    });
    expect(findTaintedSinks(code, 'default.ts').map((s) => s.sink).sort()).toEqual(['exec', 'fs.readFileSync']);
  });

  it('follows namespace imports and a .js specifier naming TypeScript source', () => {
    const code = joined({
      'src/index.ts': `import * as h from './helpers.js';\nserver.tool('run', {}, async (args) => h.runIt(args.cmd));`,
      'src/helpers.ts': HELPERS,
    });
    expect(findTaintedSinks(code, 'ns.ts')).toEqual([expect.objectContaining({ sink: 'execSync' })]);
  });

  it('follows CommonJS: destructured require, a module object, inline require, TypeScript output', () => {
    const helpers = `const cp = require('child_process');
function runIt(c) { cp.execSync(c); }
exports.spawnIt = function (p) { cp.spawn(p); };
module.exports.evalIt = (s) => eval(s);
exports.runIt = runIt;`;
    const code = joined({
      'lib/server.js': `const { runIt } = require('./helpers');
const h = require('./helpers.js');
const helpers_1 = require("./helpers");
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const a = request.params.arguments;
  runIt(a.one);
  h.spawnIt(a.two);
  require('./helpers').evalIt(a.three);
});`,
      'lib/helpers.js': helpers,
      'lib/other.js': `const helpers_1 = require("./helpers");\nfunction go(request) { (0, helpers_1.runIt)(request.x); }`,
    });
    const sinks = findTaintedSinks(code, 'cjs.js');
    expect(sinks.map((s) => s.sink).sort()).toEqual(['cp.execSync', 'cp.spawn', 'eval']);
  });

  it('follows the calls TypeScript emits for CommonJS imports', () => {
    const code = joined({
      'dist/index.js': `"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const helpers_js_1 = require("./helpers.js");
server.tool('run', {}, async ({ cmd }) => (0, helpers_js_1.runIt)(cmd));`,
      'dist/helpers.js': `"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.runIt = void 0;
const child_process_1 = require("child_process");
const runIt = (c) => (0, child_process_1.execSync)(c);
exports.runIt = runIt;`,
    });
    expect(findTaintedSinks(code, 'tsc.js')).toEqual([expect.objectContaining({ kind: 'process', origin: 'c ← caller' })]);
  });

  it('follows module.exports = { … } objects and a default import of CommonJS', () => {
    const code = joined({
      'index.mjs': `import tools from './tools.cjs';\nserver.tool('x', {}, async ({ q }) => tools.query(q));`,
      'tools.cjs': `const { execSync } = require('child_process');\nmodule.exports = { query(q) { return execSync('grep ' + q); } };`,
    });
    expect(findTaintedSinks(code, 'obj.mjs')).toEqual([expect.objectContaining({ sink: 'execSync', origin: expect.stringContaining('q ← caller') })]);
  });

  it('follows re-exports: named, star, and a directory index', () => {
    const code = joined({
      'dist/index.js': `import { runIt, readData } from './lib';\nserver.tool('r', {}, async ({ a, b }) => { runIt(a); readData(b); });`,
      'dist/lib/index.js': `export { runIt } from './exec.js';\nexport * from './fsops.js';`,
      'dist/lib/exec.js': `import { execSync } from 'child_process';\nexport const runIt = (c) => execSync(c);`,
      'dist/lib/fsops.js': `import { readFileSync } from 'fs';\nexport function readData(p) { return readFileSync(p); }`,
    });
    expect(findTaintedSinks(code, 'reexport.js').map((s) => s.sink).sort()).toEqual(['execSync', 'readFileSync']);
  });

  it('carries input through a helper chain that crosses several modules', () => {
    const code = joined({
      'a.js': `import { b } from './b.js';\nserver.tool('t', {}, async ({ x }) => b(x));`,
      'b.js': `import { c } from './c.js';\nexport function b(v) { return c(v + '!'); }`,
      'c.js': `import { d } from './d.js';\nexport function c(w) { return d([w]); }`,
      'd.js': `import { exec } from 'child_process';\nexport function d(list) { exec(list.join(' ')); }`,
    });
    expect(findTaintedSinks(code, 'chain.js')).toEqual([expect.objectContaining({ sink: 'exec', origin: 'list ← caller' })]);
  });

  it('follows a value a helper of another module returns into a sink', () => {
    const code = joined({
      'index.js': `import fs from 'fs';\nimport { target } from './paths.js';
server.tool('read', {}, async ({ name }) => fs.readFileSync(target(name)));`,
      'paths.js': `export const target = (n) => '/srv/' + n;`,
    });
    expect(findTaintedSinks(code, 'ret.js')).toEqual([expect.objectContaining({ sink: 'fs.readFileSync', origin: expect.stringMatching(/^function\(\) ← n ← caller$/) })]);
  });

  it('treats a handler imported by reference as a tool handler', () => {
    const code = joined({
      'index.js': `import { handleRun } from './handlers.js';\nimport * as hs from './handlers.js';
server.tool('run', 'Runs', { cmd: z.string() }, handleRun);
server.registerTool('ev', { inputSchema: {} }, hs.handleEval);`,
      'handlers.js': `import { exec } from 'child_process';
export async function handleRun({ cmd }) { exec(cmd); }
export async function handleEval({ code }) { return eval(code); }`,
    });
    expect(findTaintedSinks(code, 'byref.js').map((s) => s.sink).sort()).toEqual(['eval', 'exec']);
  });

  it('ends on import cycles and re-export cycles', () => {
    const code = joined({
      'a.js': `import { b } from './b.js';\nexport * from './b.js';\nexport function a(x) { return b(x); }\nserver.tool('t', {}, async ({ x }) => a(x));`,
      'b.js': `import { a } from './a.js';\nimport { exec } from 'child_process';\nexport * from './a.js';\nexport function b(y) { exec(y); return a(y); }`,
      'c.js': `import { missing } from './a.js';\nserver.tool('u', {}, async ({ z }) => missing(z));`,
    });
    expect(findTaintedSinks(code, 'cycle.js')).toEqual([expect.objectContaining({ sink: 'exec', origin: 'y ← caller' })]);
  });

  it('does not report a helper module that confines paths to its base directory (MCP-005)', async () => {
    const code = joined({
      'dist/index.js': `import { readSafe } from './safe.js';\nserver.tool('read', {}, async ({ name }) => readSafe(name));`,
      'dist/safe.js': `import fs from 'fs';\nimport path from 'path';
const BASE = '/data';
export function readSafe(name) {
  const full = path.resolve(BASE, name);
  if (!full.startsWith(BASE + path.sep)) throw new Error('outside base');
  return fs.readFileSync(full, 'utf8');
}`,
    });
    const r = await mcp005.run(ctx(code));
    expect(r.passed).toBe(true);
  });

  it('keeps tracing neighbouring modules when a linked module would grow the group past its size cap', () => {
    const big = `export const table = [\n${'  "row",\n'.repeat(Math.ceil(MAX_GROUP_SOURCE / 8))}];\nexport function lookup(k) { return table[k]; }`;
    const code = joined({
      'dist/index.js': `import { lookup } from './big.js';\nimport { runIt } from './helpers.js';
server.tool('run', {}, async ({ cmd, k }) => { lookup(k); runIt(cmd); });`,
      'dist/big.js': big,
      'dist/helpers.js': HELPERS,
    });
    expect(big.length).toBeGreaterThan(MAX_GROUP_SOURCE);
    expect(findTaintedSinks(code, 'capped.js')).toEqual([expect.objectContaining({ sink: 'execSync', origin: 'c ← caller' })]);
  });

  it('stays fast on many modules with many exports', () => {
    const files: Record<string, string> = {};
    const count = 150;
    for (let i = 0; i < count; i++) {
      const fns = Array.from({ length: 40 }, (_, k) => `export function f${k}(v) { return ${i + 1 < count ? `m.f${k}(v)` : 'v'}; }`).join('\n');
      const next = i + 1 < count ? `import * as m from './m${i + 1}.js';\nexport * from './m${i + 1}.js';\n` : `import { exec } from 'child_process';\n`;
      files[`dist/m${i}.js`] = `${next}${fns}\nexport function run(c) { ${i + 1 < count ? 'return m.run(c);' : 'exec(c);'} }`;
    }
    files['dist/index.js'] = `import { f3, run } from './m0.js';\nserver.tool('t', {}, async ({ c }) => { f3(c); run(c); });`;
    const started = performance.now();
    findTaintedSinks(joined(files), 'many.js');
    expect(performance.now() - started).toBeLessThan(5000);
  });
});
