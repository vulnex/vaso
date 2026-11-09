import { describe, it, expect } from 'vitest';
import type { ScanContext } from '../../core/types.js';
import type { MCPServerSource } from '../../mcp/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { mapSourceEvidence } from '../../mcp/source-locations.js';
import { mcp032 } from './mcp-032-env-dump-tool.js';

const ctx = (sources: MCPServerSource[]): ScanContext => ({
  installation: { agent: 'mcp', installDir: '/tmp', configFiles: [] },
  configs: [],
  platform: 'darwin',
  fs: new LocalFSProvider(),
  mcpServerSources: sources,
});
const run = (code: string) => mcp032.run(ctx([{ serverName: 's', localPath: '/srv/index.js', sourceCode: code }]));

describe('dt20 g3-F2: MCP-032 false positives (@sentry/mcp-server)', () => {
  it.each([
    // a/ an OpenTelemetry attribute name
    ['const ATTR = { "process.environment_variable": { description: "env var" } };'],
    ['const k = "process.envelope";'],
    ['const k = process["env"]["API_BASE"]; const j = process["env"].TOKEN;'],
    // c/ a getter default for a caller-supplied env
    ['function nx(e={}){ let t = e.env ?? (() => process.env); return t; }'],
    ['let t = o.env || ( ( ) => process.env );'],
    // d/ a child environment overriding variables, passed as env
    ['function rf(e,t){ let n = t?.PATH !== void 0 ? {...process.env, PATH: t.PATH} : void 0; return execFileSync("which",[e],{env:n}); }'],
    ['const n = { ...process.env, "NODE_OPTIONS": "" }; spawn(cmd, { env: n });'],
  ])('%s', async (code) => {
    expect((await run(code)).passed).toBe(true);
  });
});

describe('dt20 g3-F2: MCP-032 still flags dumps', () => {
  it.each([
    ['return { text: JSON.stringify(process.env) };'],
    ['const all = { ...process.env };'],
    ['return { ...process.env, EXTRA: 1 };'],
    ['text: JSON.stringify({ ...process.env, PATH: "/bin" })'],
    ['const x = process.env; return x;'],
    // dt20 g3 re-verify: bracket access
    ['const e = process["env"]; return { text: JSON.stringify(e) };'],
    ["return { text: JSON.stringify(process['env']) };"],
  ])('%s', async (code) => {
    expect((await run(code)).passed).toBe(false);
  });

  it('evidence carries the line, mapped to the file of a multi-file source', async () => {
    const source: MCPServerSource = {
      serverName: 's',
      localPath: '/srv/index.js',
      sourceRoot: '/srv',
      sourceCode: '// === index.js ===\nimport "./tools/env.js";\n\n// === tools/env.js ===\nconst a = 1;\nreturn { text: JSON.stringify(process.env) };',
    };
    const result = await mcp032.run(ctx([source]));
    expect(result.evidence?.[0].line).toBe(6);
    mapSourceEvidence([result], [source]);
    expect(result.evidence?.[0].file).toBe('/srv/tools/env.js');
    expect(result.evidence?.[0].line).toBe(2);
  });

  it('counts servers, one evidence item per reason', async () => {
    const result = await run('const a = JSON.stringify(process.env);\nexecSync("printenv");');
    expect(result.evidence).toHaveLength(2);
    expect(result.evidence?.map((e) => e.line)).toEqual([1, 2]);
    expect(result.message).toBe('Found 1 MCP server(s) exposing the full process environment');
  });
});
