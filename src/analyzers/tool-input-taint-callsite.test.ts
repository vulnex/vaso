import { describe, it, expect } from 'vitest';
import { MAX_GROUP_SOURCE, findTaintedSinks, findUnverifiedSinks, moduleWeight, taintCoverage } from './tool-input-taint.js';
import { escapeFileMarkers, significantLength, sourceChunks } from './js-parse.js';
import type { MCPServerSource, ScanContext } from '../core/types.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { mcp001 } from '../checks/mcp/mcp-001-config-discovery.js';
import { mcp004 } from '../checks/mcp/mcp-004-overprivileged-tools.js';
import { mcp005 } from '../checks/mcp/mcp-005-tool-injection.js';

/** Files joined the way the source resolver joins a server's modules. */
const joined = (files: Record<string, string>): string =>
  Object.entries(files).map(([path, code]) => `// === ${path} ===\n${escapeFileMarkers(code)}`).join('\n\n');

const RUN = `import { execSync } from 'node:child_process';\nexport function run(c) { return execSync(c); }`;
const TOOL = `import { run } from './h.js';\nserver.tool('run', 'd', { cmd: z.string() }, async ({ cmd }) => { run(cmd); });`;

let n = 0;
const ctx = (source: Partial<MCPServerSource>): ScanContext => ({
  installation: { agent: 'mcp', installDir: '/tmp', configFiles: [] },
  configs: [], platform: 'darwin', fs: new LocalFSProvider(),
  mcpConfigs: [],
  mcpServerSources: [{ serverName: `c${++n}`, localPath: `/tmp/callsite-${n}.js`, ...source } as MCPServerSource],
} as ScanContext);

describe('return values are traced per call site', () => {
  it('does not taint startup code that calls a helper the handler also calls (across modules)', () => {
    const code = joined({
      'server.js': `import { norm } from './util.js';\nimport { startup } from './boot.js';
server.tool('echo', 'e', { text: z.string() }, async ({ text }) => ({ content: [{ type: 'text', text: norm(text) }] }));
startup();`,
      'util.js': `export function norm(s) { return String(s).trim(); }`,
      'boot.js': `import { execSync } from 'node:child_process';\nimport { norm } from './util.js';
const GIT = 'git rev-parse HEAD';
export function startup() { return execSync(norm(GIT)).toString(); }`,
    });
    expect(findTaintedSinks(code, 'ctx-cross.js')).toEqual([]);
  });

  it('does not taint startup code in the same file either', () => {
    const code = `import { execSync } from 'node:child_process';
function norm(s) { return String(s).trim(); }
function startup() { return execSync(norm('git rev-parse HEAD')).toString(); }
server.tool('echo', 'e', {}, async ({ text }) => ({ content: [{ type: 'text', text: norm(text) }] }));
startup();`;
    expect(findTaintedSinks(code, 'ctx-same.js')).toEqual([]);
  });

  it('still taints the call site that passes tool input, naming the argument', () => {
    const code = `import { execSync } from 'node:child_process';
function norm(s) { return String(s).trim(); }
execSync(norm('uptime'));
server.tool('run', 'r', {}, async ({ cmd }) => execSync(norm(cmd)));`;
    expect(findTaintedSinks(code, 'ctx-tp.js')).toEqual([
      expect.objectContaining({ line: 4, sink: 'execSync', origin: 'norm() ← s ← cmd' }),
    ]);
  });

  it('follows each argument a helper returns, not only the first', () => {
    const code = `import { exec } from 'child_process';
function join(a, b) { return a + ' ' + b; }
server.tool('run', 'r', {}, async ({ cmd }) => exec(join('ls', cmd)));`;
    expect(findTaintedSinks(code, 'ctx-second.js')).toEqual([expect.objectContaining({ sink: 'exec', origin: 'join() ← b ← cmd' })]);
  });

  it('carries input through a helper that returns another helper\'s result', () => {
    const code = `import { exec } from 'child_process';
const quote = (v) => '"' + v + '"';
function build(x) { return 'grep ' + quote(x); }
exec(build('fixed'));
server.tool('run', 'r', {}, async ({ q }) => exec(build(q)));`;
    expect(findTaintedSinks(code, 'ctx-nested.js').map((s) => s.line)).toEqual([5]);
  });
});

describe('helper chains of any length, in any order', () => {
  it('follows a 10-hop chain declared against the walk (same file)', () => {
    const fns = Array.from({ length: 10 }, (_, i) => (i === 9 ? 'function f9(x) { return execSync(x); }' : `function f${i}(x) { return f${i + 1}(x); }`)).reverse();
    const code = `import { execSync } from 'node:child_process';\n${fns.join('\n')}\nserver.tool('run', 'd', {}, async ({ cmd }) => { f0(cmd); });`;
    expect(findTaintedSinks(code, 'rev10.js')).toEqual([expect.objectContaining({ sink: 'execSync' })]);
  });

  it('follows a 9-module chain imported against the walk', () => {
    const files: Record<string, string> = {};
    files['server.js'] = `${Array.from({ length: 8 }, (_, i) => `import './m${8 - i}.js';`).join('\n')}\nimport { f1 } from './m1.js';
server.tool('run', 'd', {}, async ({ cmd }) => { f1(cmd); });`;
    for (let i = 1; i <= 8; i++) {
      files[`m${i}.js`] = i < 8
        ? `import { f${i + 1} } from './m${i + 1}.js';\nexport function f${i}(x) { return f${i + 1}(x); }`
        : `import { execSync } from 'node:child_process';\nexport function f8(x) { return execSync(x); }`;
    }
    expect(findTaintedSinks(joined(files), 'revmods.js')).toEqual([expect.objectContaining({ sink: 'execSync' })]);
  });
});

describe('allow-list guards in helpers', () => {
  it('does not report an exec a helper guards with an allow-list (across modules and in one file)', () => {
    const allow = `import { execSync } from 'node:child_process';
const ALLOWED = ['ls', 'pwd', 'whoami'];
export function runAllowed(c) { if (!ALLOWED.includes(c)) throw new Error('no'); return execSync(c); }`;
    expect(findTaintedSinks(joined({
      'server.js': `import { runAllowed } from './allow.js';\nserver.tool('run', 'r', {}, async ({ cmd }) => { runAllowed(cmd); });`,
      'allow.js': allow,
    }), 'allow-cross.js')).toEqual([]);
    expect(findTaintedSinks(`${allow.replace('export ', '')}\nserver.tool('run', 'r', {}, async ({ cmd }) => { runAllowed(cmd); });`, 'allow-same.js')).toEqual([]);
  });

  it('still reports the exec when the guard does not leave', () => {
    const code = `import { execSync } from 'node:child_process';
const ALLOWED = ['ls'];
function run(c) { if (!ALLOWED.includes(c)) console.warn('odd'); return execSync(c); }
server.tool('run', 'r', {}, async ({ cmd }) => { run(cmd); });`;
    expect(findTaintedSinks(code, 'allow-noexit.js')).toEqual([expect.objectContaining({ sink: 'execSync' })]);
  });

  it('guards file paths too', () => {
    const code = `import fs from 'fs';
function read(name) { if (name !== 'a.txt' && name !== 'b.txt') return null; return fs.readFileSync(name); }
server.tool('read', 'r', {}, async ({ name }) => read(name));`;
    expect(findTaintedSinks(code, 'allow-fs.js')).toEqual([]);
  });
});

describe('TypeScript CommonJS output and other export forms', () => {
  const H = `"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.run = run;
exports.default = run;
const child_process_1 = require("child_process");
function run(c) {
    return (0, child_process_1.execSync)(c);
}`;
  const server = (head: string, call: string): string => `"use strict";
${head}
server.tool("run", "runs", { cmd: zod_1.z.string() }, async ({ cmd }) => {
    ${call}(cmd);
});`;
  const STAR = `var __importStar = (this && this.__importStar) || function (mod) { return mod; };`;
  const DEFAULT = `var __importDefault = (this && this.__importDefault) || function (mod) { return mod; };`;

  it.each([
    ['__importStar(require(…))', { 'dist/server.js': server(`${STAR}\nconst h = __importStar(require("./h"));`, 'h.run'), 'dist/h.js': H }],
    ['tslib __importStar', { 'dist/server.js': server(`const h = tslib_1.__importStar(require("./h"));`, 'h.run'), 'dist/h.js': H }],
    ['__importDefault(require(…)).default', { 'dist/server.js': server(`${DEFAULT}\nconst h_1 = __importDefault(require("./h"));`, '(0, h_1.default)'), 'dist/h.js': H }],
    ['__exportStar barrel', {
      'dist/server.js': server('const lib_1 = require("./lib");', '(0, lib_1.run)'),
      'dist/lib/index.js': `var __exportStar = function(m, exports) {};\n__exportStar(require("./h"), exports);`,
      'dist/lib/h.js': H,
    }],
    ['Object.defineProperty getter barrel', {
      'dist/server.js': server('const lib_1 = require("./lib");', '(0, lib_1.run)'),
      'dist/lib/index.js': `exports.run = void 0;\nvar h_1 = require("./h");\nObject.defineProperty(exports, "run", { enumerable: true, get: function () { return h_1.run; } });`,
      'dist/lib/h.js': H,
    }],
    ['exports.run = h_1.run', {
      'dist/server.js': server('const lib_1 = require("./lib");', '(0, lib_1.run)'),
      'dist/lib/index.js': `const h_1 = require("./h");\nexports.run = h_1.run;`,
      'dist/lib/h.js': H,
    }],
    ['export default of a constant object', {
      'server.js': `import h from './h.js';\nserver.tool('run', 'r', {}, async ({ cmd }) => { h.run(cmd); });`,
      'h.js': `import { execSync } from 'node:child_process';\nconst h = { run(c) { return execSync(c); } };\nexport default h;`,
    }],
    ['import then export', {
      'server.js': `import { run } from './lib/index.js';\nserver.tool('run', 'r', {}, async ({ cmd }) => { run(cmd); });`,
      'lib/index.js': `import { run } from './h.js';\nexport { run };`,
      'lib/h.js': RUN,
    }],
    ['module.exports = a constant object of required functions', {
      'server.js': `const api = require('./api');\nserver.tool('run', 'r', {}, async ({ cmd }) => { api.run(cmd); });`,
      'api.js': `const { run } = require('./h');\nconst api = { run };\nmodule.exports = api;`,
      'h.js': `const { execSync } = require('child_process');\nexports.run = function (c) { return execSync(c); };`,
    }],
  ])('follows %s', (_, files) => {
    expect(findTaintedSinks(joined(files as Record<string, string>), 'tsc.js')).toEqual([
      expect.objectContaining({ kind: 'process', origin: 'c ← caller' }),
    ]);
  });

  it('resolves a sink module TypeScript wraps in __importStar', () => {
    const code = `const cp = __importStar(require("child_process"));\nserver.tool("run", "r", {}, async ({ cmd }) => { cp.execSync(cmd); });`;
    expect(findTaintedSinks(code, 'star-sink.js')).toEqual([expect.objectContaining({ sink: 'cp.execSync' })]);
  });
});

describe('module groups grow from the tool handlers', () => {
  const pad = (bytes: number): string => `/* ${'y'.repeat(bytes)} */`;
  const realPad = (bytes: number): string => Array.from({ length: Math.ceil(bytes / 70) }, (_, i) => `export const k${i} = "${'x'.repeat(48)}";`).join('\n');
  /** Code, no sink: functions the AST holds in full. */
  const codePad = (bytes: number): string => Array.from({ length: Math.ceil(bytes / 50) }, (_, i) => `export function k${i}(a) { return a + ${i}; }`).join('\n');
  /** Code with sinks of its own, fixed commands. */
  const sinkPad = (bytes: number): string => `import { execSync as x } from 'node:child_process';\n${Array.from({ length: Math.ceil(bytes / 50) }, (_, i) => `export function k${i}() { return x('ls'); }`).join('\n')}`;

  it('does not count comments against the size cap', () => {
    expect(significantLength(`${pad(600_000)}\nconst a = 1;`)).toBeLessThan(MAX_GROUP_SOURCE);
    expect(significantLength('const  a =\n  "x  y"; // note')).toBe('consta="x  y";'.length);
    // never less than an eighth: a `/*` the scan can't tell from a regex doesn't hide code
    expect(significantLength(`const r = /[/*]/;\n${'a();'.repeat(100_000)}`)).toBeGreaterThanOrEqual(50_000);
  });

  it('traces a helper padded with a large comment, and one imported after a large sibling', () => {
    const helper = joined({ 'server.js': TOOL, 'h.js': `${pad(530_000)}\n${RUN}` });
    expect(findTaintedSinks(helper, 'pad-helper.js')).toEqual([expect.objectContaining({ sink: 'execSync' })]);
    const sibling = joined({ 'server.js': `import './pad.js';\n${TOOL}`, 'pad.js': codePad(800_000), 'h.js': RUN });
    expect(findTaintedSinks(sibling, 'pad-sibling.js')).toEqual([expect.objectContaining({ sink: 'execSync' })]);
    expect(taintCoverage(sibling).untraced).toEqual([expect.objectContaining({ path: 'pad.js', from: 'server.js' })]);
  });

  it('admits the modules that lead to a sink before sink-free ones imported first', () => {
    // two big code modules imported before the one that runs the input
    const code = joined({
      'server.js': `import './pad1.js';\nimport './pad2.js';\n${TOOL}`,
      'pad1.js': codePad(400_000), 'pad2.js': codePad(400_000), 'h.js': RUN,
    });
    expect(findTaintedSinks(code, 'sink-first.js')).toEqual([expect.objectContaining({ sink: 'execSync', origin: 'c ← caller' })]);
    expect(taintCoverage(code).untraced).toEqual([expect.objectContaining({ path: 'pad2.js' })]);
    // also through a sink-free module in between
    const via = joined({
      'server.js': `import './pad1.js';\nimport './pad2.js';\nimport { run } from './mid.js';\nserver.tool('run', 'd', { cmd: z.string() }, async ({ cmd }) => { run(cmd); });`,
      'pad1.js': codePad(400_000), 'pad2.js': codePad(400_000), 'mid.js': `export { run } from './h.js';`, 'h.js': RUN,
    });
    expect(findTaintedSinks(via, 'sink-first-via.js')).toEqual([expect.objectContaining({ sink: 'execSync' })]);
  }, 30_000);

  it('counts string tables at their literal cost, not their length', () => {
    const table = `export const A = [${Array.from({ length: 6_000 }, () => `"${'x'.repeat(40)}"`).join(',')}];`;
    expect(table.length).toBeGreaterThan(250_000);
    expect(moduleWeight(table)).toBeLessThan(60_000);
    // numbers sit outside strings: counted in full
    const numbers = `export const N = [${Array.from({ length: 60_000 }, (_, i) => i).join(',')}];`;
    expect(moduleWeight(numbers)).toBe(significantLength(numbers));
    // anything that runs code is not a data module
    for (const code of [
      `export const A = ["x", f("y")];`, `export const A = () => "x";`, `export const A = run\`x\`;`,
      'export const A = `${x}`;', `export const A = new/**/Foo;`, `export const A = /x/;`, `export const A = { get x() { return 1; } };`,
      `export class A {}`, `export const A = import("./x.js");`,
    ]) expect(moduleWeight(code), code).toBe(significantLength(code));
    expect(moduleWeight(`import { B } from './b.js';\nexport const A = ["${'x'.repeat(1000)}", B];`)).toBeLessThan(100);
  });

  it('traces exec behind two ~256 KB string tables imported first (padding)', async () => {
    const table = (name: string): string => `export const ${name} = [${Array.from({ length: 6_200 }, () => `"${'q'.repeat(40)}"`).join(',')}];`;
    const code = joined({
      'index.js': `import { A } from "./pad1.js";\nimport { B } from "./pad2.js";\nimport { run } from "./lib.js";\nserver.tool("run", { cmd: z.string() }, async (args) => { run(args.cmd); return { content: [{ type: "text", text: String(A.length + B.length) }] }; });`,
      'pad1.js': table('A'), 'pad2.js': table('B'),
      'lib.js': `import { exec } from "node:child_process";\nexport function run(c) { exec(c); }`,
    });
    expect(findTaintedSinks(code, 'j17.js')).toEqual([expect.objectContaining({ sink: 'exec', kind: 'process' })]);
    expect(taintCoverage(code).untraced).toEqual([]);
    const r5 = await mcp005.run(ctx({ sourceCode: code, sourceRoot: '/srv/app' }));
    expect(r5.severity).toBe('critical');
  }, 30_000);

  it('reports a sink in a module left out for size as a not-verified warning (MCP-004 and MCP-005)', async () => {
    // sink-bearing padding fills the group first; the module that runs the input is left out
    const code = joined({
      'server.js': `import './pad1.js';\n${TOOL}`,
      'pad1.js': sinkPad(600_000), 'h.js': `${RUN}\n${codePad(150_000)}`,
    });
    expect(taintCoverage(code).untraced).toEqual([expect.objectContaining({ path: 'h.js' })]);
    expect(findTaintedSinks(code, 'unverified.js')).toEqual([]);
    expect(findUnverifiedSinks(code, 'unverified.js')).toEqual([expect.objectContaining({ sink: 'execSync', unverified: true })]);

    const r4 = await mcp004.run(ctx({ sourceCode: code, sourceRoot: '/srv/app' }));
    expect(r4.severity).toBe('warning');
    expect(r4.message).toMatch(/not verified for some: cross-module analysis incomplete/);
    expect(r4.message).not.toMatch(/none reached by tool input/);
    const exec = r4.evidence?.find((e) => /execSync\(\) call/.test(e.detail ?? '') && /h\.js/.test(e.detail ?? ''));
    expect(exec?.detail).toMatch(/not verified: cross-module analysis incomplete/);

    const r5 = await mcp005.run(ctx({ sourceCode: code, sourceRoot: '/srv/app' }));
    expect(r5.passed).toBe(false);
    expect(r5.severity).toBe('warning');
    expect(r5.evidence).toEqual([expect.objectContaining({
      detail: expect.stringMatching(/^not verified: cross-module analysis incomplete — execSync\(\) in h\.js/),
    })]);
  }, 30_000);

  it('does not call a fixed command in a module left out for size unverified', async () => {
    const code = joined({
      'server.js': `import './pad1.js';\nimport { ls } from './h.js';\nserver.tool('ls', 'd', {}, async () => ls());`,
      'pad1.js': sinkPad(600_000),
      'h.js': `import { execSync } from 'node:child_process';\nexport function ls() { return execSync('ls'); }\n${codePad(150_000)}`,
    });
    expect(taintCoverage(code).untraced).toEqual([expect.objectContaining({ path: 'h.js' })]);
    expect(findUnverifiedSinks(code, 'fixed.js')).toEqual([]);
    const r5 = await mcp005.run(ctx({ sourceCode: code, sourceRoot: '/srv/app' }));
    expect(r5.passed).toBe(true);
  }, 30_000);

  it('puts the handler file first even when an unrelated module comes first in the source', () => {
    const code = joined({ 'a-big.js': `import './h.js';\n${realPad(500_000)}`, 'server.js': TOOL, 'h.js': RUN });
    expect(findTaintedSinks(code, 'order.js')).toEqual([expect.objectContaining({ sink: 'execSync' })]);
    expect(taintCoverage(code).untraced).toEqual([]);
  });

  it('reports a module left out for size: MCP-001 says so and MCP-004 does not call its exec clean', async () => {
    const code = joined({ 'server.js': TOOL, 'h.js': `${RUN}\n${realPad(600_000)}` });
    expect(findTaintedSinks(code, 'big.js')).toEqual([]);
    const { untraced } = taintCoverage(code);
    expect(untraced).toEqual([expect.objectContaining({ path: 'h.js', from: 'server.js' })]);
    const lines = code.split('\n');
    expect(lines[untraced[0].startLine - 1]).toBe('// === h.js ===');
    expect(lines[untraced[0].endLine - 1]).toMatch(/export const k\d+/);

    const r1 = await mcp001.run(ctx({ sourceCode: code, sourceRoot: '/srv/app' }));
    expect(r1.passed).toBe(false);
    expect(r1.message).toMatch(/not traced across all their modules \(size limit\)/);
    expect(r1.evidence).toEqual(expect.arrayContaining([expect.objectContaining({
      file: '/srv/app/h.js',
      detail: expect.stringContaining('cross-module analysis incomplete: h.js not followed from server.js (size limit)'),
    })]));
    const r4 = await mcp004.run(ctx({ sourceCode: code, sourceRoot: '/srv/app' }));
    const exec = r4.evidence?.find((e) => /execSync/.test(e.detail ?? ''));
    expect(exec?.detail).toMatch(/not verified: cross-module analysis incomplete — the command is built at runtime and tool input was not traced into h\.js \(size limit\)/);
    expect(exec?.detail).not.toMatch(/no tool input was traced/);
    expect(r4.severity).toBe('warning');
    const r5 = await mcp005.run(ctx({ sourceCode: code, sourceRoot: '/srv/app' }));
    expect(r5.severity).toBe('warning');
    expect(r5.evidence?.[0]?.detail).toMatch(/not verified/);
  });

  describe('a helper shared by handler files in different groups', () => {
    const INDEX = `export const server = new McpServer({ name: "x", version: "1" });\nimport "./a.js";\nimport "./b.js";`;
    const LIB = `import { exec } from "node:child_process";\nexport function run(c) { exec(c); }`;
    const A = `import { server } from "./index.js";\nimport { run } from "./lib.js";\nimport { f0 } from "./pad.js";\nserver.tool("status", {}, async () => { run("git status"); return { content: [{ type: "text", text: f0("x") }] }; });`;
    const B = `import { server } from "./index.js";\nimport { run } from "./lib.js";\nserver.tool("exec", { cmd: z.string() }, async (args) => { run(args.cmd); return { content: [] }; });`;
    /** Lines of `line(i)` weighing at least `target`. */
    const padTo = (target: number, line: (i: number) => string, head: string[] = []): string => {
      const lines = [...head];
      for (let i = 0, w = 0; w < target; i++) {
        lines.push(line(i));
        w += significantLength(line(i));
      }
      return lines.join('\n');
    };
    /** Code holding real sinks (fills a.js's group). */
    const sinkPadTo = (target: number): string => padTo(target, (i) => `export function k${i}() { return x('ls'); }`, [`import { execSync as x } from 'node:child_process';`]);
    /** Code, no sink. */
    const codePadTo = (target: number): string => padTo(target, (i) => `export function m${i}(a) { return a + ${i}; }`);

    it('a decoy `exec(` comment or string does not promote a padding module over a handler file (dt24 e5)', async () => {
      // small functions, no sink, filling a.js's group to just under the cap: b.js fits only if it joins before
      const room = MAX_GROUP_SOURCE - [INDEX, A, LIB].reduce((w, c) => w + moduleWeight(c), 0) - 110;
      const fnPad = (decoy: string): string => padTo(room, (i) => `export function f${i}(a) { return a + "${'q'.repeat(30)}"; }`, [decoy]);
      expect(moduleWeight(B)).toBeGreaterThan(100);
      for (const decoy of ['// exec( decoy', 'const d = "exec(";', '/* spawn( */ const t = `fs ${1} exec(`;']) {
        const code = joined({ 'index.js': INDEX, 'a.js': A, 'b.js': B, 'lib.js': LIB, 'pad.js': fnPad(decoy) });
        expect(findTaintedSinks(code, `e5-${decoy}.js`), decoy).toEqual([expect.objectContaining({ sink: 'exec', origin: 'c ← caller' })]);
        const r4 = await mcp004.run(ctx({ sourceCode: code, sourceRoot: '/srv/app' }));
        expect(r4.severity, decoy).toBe('critical');
        const r5 = await mcp005.run(ctx({ sourceCode: code, sourceRoot: '/srv/app' }));
        expect(r5.severity, decoy).toBe('critical');
      }
    }, 60_000);

    it('traces a small helper in both groups when real sink code fills the first', async () => {
      const pad = sinkPadTo(MAX_GROUP_SOURCE - 20_000);
      const b = `${B}\n${codePadTo(30_000)}`;
      const code = joined({ 'index.js': INDEX, 'a.js': A, 'b.js': b, 'lib.js': LIB, 'pad.js': pad });
      expect(findTaintedSinks(code, 'shared-helper.js')).toEqual([expect.objectContaining({ sink: 'exec', origin: 'c ← caller' })]);
      expect(taintCoverage(code).untraced).toEqual([]);
      const r5 = await mcp005.run(ctx({ sourceCode: code, sourceRoot: '/srv/app' }));
      expect(r5.severity).toBe('critical');
      expect(r5.evidence).toHaveLength(1);
    }, 60_000);

    it('traces a shared helper reached through a re-export', () => {
      const pad = sinkPadTo(MAX_GROUP_SOURCE - 20_000);
      const index = `${INDEX}\nexport { run } from "./lib.js";`;
      const b = `import { server, run } from "./index.js";\nserver.tool("exec", { cmd: z.string() }, async (args) => { run(args.cmd); return { content: [] }; });\n${codePadTo(30_000)}`;
      const code = joined({ 'index.js': index, 'a.js': A, 'b.js': b, 'lib.js': LIB, 'pad.js': pad });
      expect(findTaintedSinks(code, 'shared-reexport.js')).toEqual([expect.objectContaining({ sink: 'exec' })]);
    }, 60_000);

    it('two handler files sharing a helper, no padding: critical', async () => {
      const code = joined({ 'index.js': INDEX, 'a.js': A.replace(/\nimport \{ f0 \}.*\n/, '\n').replace('f0("x")', '"x"'), 'b.js': B, 'lib.js': LIB });
      expect(findTaintedSinks(code, 'shared-nopad.js')).toEqual([expect.objectContaining({ sink: 'exec' })]);
      const r4 = await mcp004.run(ctx({ sourceCode: code, sourceRoot: '/srv/app' }));
      expect(r4.severity).toBe('critical');
    });

    it('records a helper one group left out for size even when a later group takes it in', async () => {
      const pad = sinkPadTo(MAX_GROUP_SOURCE - 20_000);
      // a.js passes tool input, b.js a constant; lib.js fits only b.js's group
      const a = `import { server } from "./index.js";\nimport { f0 } from "./pad.js";\nimport { run } from "./lib.js";\nserver.tool("exec", { cmd: z.string() }, async (args) => { run(args.cmd); return { content: [{ type: "text", text: f0("x") }] }; });`;
      const b = `import { server } from "./index.js";\nimport { run } from "./lib.js";\nserver.tool("status", {}, async () => { run("git status"); return { content: [] }; });\n${codePadTo(30_000)}`;
      const lib = `${LIB}\n${codePadTo(30_000)}`;
      const code = joined({ 'index.js': INDEX, 'a.js': a, 'b.js': b, 'lib.js': lib, 'pad.js': pad });
      expect(taintCoverage(code).untraced).toEqual([expect.objectContaining({ path: 'lib.js', from: 'a.js' })]);
      const r5 = await mcp005.run(ctx({ sourceCode: code, sourceRoot: '/srv/app' }));
      expect(r5.passed).toBe(false);
      expect(r5.evidence?.[0]?.detail).toMatch(/not verified/);
    }, 60_000);

    it('records a link into a helper too big to share as not followed (not verified, never clean)', async () => {
      const pad = sinkPadTo(MAX_GROUP_SOURCE - 100_000);
      const lib = `${LIB}\n${codePadTo(80_000)}`;
      const b = `${B}\n${codePadTo(30_000)}`;
      const code = joined({ 'index.js': INDEX, 'a.js': A, 'b.js': b, 'lib.js': lib, 'pad.js': pad });
      expect(taintCoverage(code).untraced).toEqual([expect.objectContaining({ path: 'lib.js', from: 'b.js' })]);
      expect(findUnverifiedSinks(code, 'shared-big.js')).toEqual([expect.objectContaining({ sink: 'exec', unverified: true })]);
      const r4 = await mcp004.run(ctx({ sourceCode: code, sourceRoot: '/srv/app' }));
      expect(r4.severity).toBe('warning');
      expect(r4.message).not.toMatch(/none reached by tool input/);
    }, 60_000);
  });

  it('leaves MCP-001 passing when every module was followed', async () => {
    const r1 = await mcp001.run(ctx({ sourceCode: joined({ 'server.js': TOOL, 'h.js': RUN }), sourceRoot: '/srv/app' }));
    expect(r1.passed).toBe(true);
  });
});

describe('file headers come only from the joiner', () => {
  it('escapes a header-shaped line inside a file, keeping its line count', () => {
    const text = 'export const v = 1;\n// === h.js ===\nexport function run(c) { return c; }';
    const escaped = escapeFileMarkers(text);
    expect(escaped.split('\n')).toHaveLength(3);
    expect(escaped).toContain('//  === h.js ===');
    expect(sourceChunks(escaped)).toHaveLength(1);
  });

  it('does not let a decoy header in one module stand in for the real one', () => {
    const code = joined({
      'aaa.js': `export const version = "1.0.0";\n// === h.js ===\nexport function run(c) { return c; }`,
      'h.js': RUN,
      'server.js': `import { version } from './aaa.js';\n${TOOL}`,
    });
    expect(findTaintedSinks(code, 'decoy.js')).toEqual([expect.objectContaining({ sink: 'execSync', origin: 'c ← caller' })]);
  });
});
