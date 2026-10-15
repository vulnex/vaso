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

describe('maskCredentialsInText', () => {
  it('masks URL passwords, token userinfo, secret query values and --token args, keeping the rest', async () => {
    const { maskCredentialsInText } = await import('./serialize.js');
    expect(maskCredentialsInText('URL: https://alice:HUNTER2PASSWORD@evil.example.com/sse?access_token=SECRETQ&apikey=QWERTY&page=2'))
      .toBe('URL: https://alice:***@evil.example.com/sse?access_token=***&apikey=***&page=2');
    expect(maskCredentialsInText('https://ghp_abcdefghijklmnopqrstuvwx@github.com/o/r')).toBe('https://***@github.com/o/r');
    expect(maskCredentialsInText('Args: -y some-pkg --token=ARGTOKEN --api-key KEY2 --port 80'))
      .toBe('Args: -y some-pkg --token=*** --api-key *** --port 80');
    expect(maskCredentialsInText('git@github.com:o/r.git and http://127.0.0.1:8080/mcp')).toBe('git@github.com:o/r.git and http://127.0.0.1:8080/mcp');
  });

  it('is applied by every reporter', async () => {
    const { getReporter } = await import('./index.js');
    const scan = {
      timestamp: 't', agents: [{ agent: 'mcp', installation: { agent: 'mcp', installDir: '/x', configFiles: [] }, score: 0, grade: 'F',
        results: [{ id: 'MCP-002', name: 'n', category: 'mcp', severity: 'warning', passed: false, message: 'm',
          evidence: [{ file: '/x/mcp.json', detail: 'URL: http://bob:PROJPASS999@10.0.0.5/mcp?key=PROJQUERYKEY000' }] }] }],
      totalScore: 0, totalGrade: 'F', fleetAverage: 0, summary: { critical: 0, warning: 1, info: 0, passed: 0, total: 1 },
    } as never;
    for (const f of ['terminal', 'json', 'csv', 'junit', 'markdown', 'html', 'sarif']) {
      const out = getReporter(f).render(scan);
      expect(out, f).not.toMatch(/PROJPASS999|PROJQUERYKEY000/);
    }
  });
});
