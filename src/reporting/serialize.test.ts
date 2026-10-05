import { describe, it, expect } from 'vitest';
import { toReportJson } from './serialize.js';

const SECRET = 'sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE';

describe('toReportJson', () => {
  it('keeps config file paths and formats but never their contents', () => {
    const out = toReportJson({
      agents: [{ installation: { agent: 'x', configFiles: [{ filePath: '/h/.x/config.json', format: 'json', raw: `{"key":"${SECRET}"}`, data: { key: SECRET } }] } }],
    });
    expect(out).not.toContain(SECRET);
    expect(JSON.parse(out).agents[0].installation.configFiles).toEqual([{ filePath: '/h/.x/config.json', format: 'json' }]);
  });

  it('masks MCP server env and headers values, keeping the keys', () => {
    const token = 'ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE00';
    const out = JSON.parse(toReportJson({
      configs: [{ servers: [{ name: 'gh', env: { GITHUB_TOKEN: token, DEBUG: '1' }, headers: { Authorization: `Bearer ${SECRET}` } }] }],
    }));
    const server = out.configs[0].servers[0];
    expect(server.env).toEqual({ GITHUB_TOKEN: `ghp_…(${token.length} chars)`, DEBUG: '***' });
    expect(server.headers.Authorization).toBe(`Bear…(${SECRET.length + 7} chars)`);
  });

  it('leaves everything else untouched', () => {
    const value = { timestamp: 't', agents: [{ results: [{ id: 'CFG-001', evidence: [{ file: '/a', snippet: 'x' }] }] }] };
    expect(JSON.parse(toReportJson(value))).toEqual(value);
  });
});
