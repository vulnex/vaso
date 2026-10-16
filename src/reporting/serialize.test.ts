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

describe('credential masking: every payload, every output path', () => {
  /** [quoted text, secret that must not survive] — shapes seen in real MCP configs. */
  const TEXT: Array<[string, string]> = [
    ['https://evil.example.com/sse#access_token=FRAG0001', 'FRAG0001'],
    ['http://b.s3.amazonaws.com/m?X-Amz-Credential=AKIAQQQQ0002&X-Amz-Signature=SIG0003', 'AKIAQQQQ0002'],
    ['http://b.s3.amazonaws.com/m?X-Amz-Credential=AKIAQQQQ0002&X-Amz-Signature=SIG0003', 'SIG0003'],
    ['http://gl.example.com/m?private_token=GLPAT0004&jwt=JWT0005&session=SESS0006', 'GLPAT0004'],
    ['http://gl.example.com/m?private_token=GLPAT0004&jwt=JWT0005&session=SESS0006', 'JWT0005'],
    ['http://gl.example.com/m?private_token=GLPAT0004&jwt=JWT0005&session=SESS0006', 'SESS0006'],
    ['http://u:P4ss@word0007@host.example.com/mcp', 'word0007'],
    ["http://u:pa'ss0008@host.example.com/mcp", 'ss0008'],
    ['http://hooks.slack.com/services/T0/B0/SLACK0009', 'SLACK0009'],
    ['http://api.telegram.org/bot123456:TG0010/mcp', 'TG0010'],
    ['npx mcp-remote https://r.example.com/sse --header Authorization: Bearer HDR0011', 'HDR0011'],
    ['docker run -e GITHUB_PERSONAL_ACCESS_TOKEN=ghp_DOCK0012 img', 'DOCK0012'],
    ['npx pkg --token TOK0013 --key=KEY0014 --pat=PAT0015 -p PW0016', 'TOK0013'],
    ['npx pkg --token TOK0013 --key=KEY0014 --pat=PAT0015 -p PW0016', 'KEY0014'],
    ['npx pkg --token TOK0013 --key=KEY0014 --pat=PAT0015 -p PW0016', 'PAT0015'],
    ['npx pkg --token TOK0013 --key=KEY0014 --pat=PAT0015 -p PW0016', 'PW0016'],
    ['sh -c "API_KEY=SH0017 curl -u admin:CURL0018 http://x.example.com"', 'SH0017'],
    ['sh -c "API_KEY=SH0017 curl -u admin:CURL0018 http://x.example.com"', 'CURL0018'],
    ['env OPENAI_API_KEY=sk-proj-ENV0019 npx foo', 'ENV0019'],
    ['curl -H "X-Api-Key: XAK0020" https://api.example.com', 'XAK0020'],
  ];
  /** argv arrays: the value is a separate element. */
  const ARGV: Array<[string[], string]> = [
    [['mcp-remote', 'https://r.example.com/sse', '--header', 'Authorization: Bearer HDR0101'], 'HDR0101'],
    [['run', '-e', 'SLACK_BOT_TOKEN=xoxb-DOCK0102'], 'DOCK0102'],
    [['pkg', '--token', 'TOK0103'], 'TOK0103'],
    [['pkg', '--password', 'PW0104'], 'PW0104'],
    [['pkg', '-p', 'PW0105'], 'PW0105'],
    [['curl', '-u', 'admin:CURL0106'], 'CURL0106'],
  ];

  it('masks every payload in every report format', async () => {
    const { getReporter, reportFormats } = await import('./index.js');
    const result = {
      timestamp: 't', totalScore: 50, totalGrade: 'C', fleetAverage: 50,
      summary: { critical: 1, warning: 0, info: 0, passed: 0, total: 1 },
      agents: [{
        agent: 'mcp', score: 50, grade: 'C',
        installation: { agent: 'mcp', installDir: '/h', configFiles: [] },
        results: [{
          id: 'MCP-003', name: 'n', category: 'mcp', severity: 'critical', passed: false, message: TEXT[0][0],
          evidence: [...TEXT.map(([t]) => ({ file: '/h/mcp.json', snippet: t, detail: t })),
            ...ARGV.map(([a]) => ({ file: '/h/mcp.json', snippet: JSON.stringify(a), detail: 'args' }))],
        }],
        servers: ARGV.map(([args], i) => ({ name: `s${i}`, command: 'npx', args })),
      }],
    };
    for (const format of reportFormats()) {
      const out = getReporter(format).render(result as never);
      for (const [, secret] of [...TEXT, ...ARGV]) expect(out, `${format}: ${secret}`).not.toContain(secret);
    }
    const json = toReportJson(result);
    for (const [, secret] of [...TEXT, ...ARGV]) expect(json, `json: ${secret}`).not.toContain(secret);
  });

  it('masks argv arrays (mcp list) element by element', async () => {
    const { maskCredentialsDeep } = await import('./serialize.js');
    for (const [args, secret] of ARGV) expect(maskCredentialsDeep({ args }).args.join(' ')).not.toContain(secret);
  });

  it('keeps references, placeholders, ports, paths and ordinary text readable', async () => {
    const { maskCredentialsInText, maskCredentialsDeep } = await import('./serialize.js');
    const keep = [
      'https://api.example.com/mcp?token=${MCP_TOKEN}',
      'Authorization: Bearer ${GITHUB_TOKEN}',
      'docker run -e GITHUB_PERSONAL_ACCESS_TOKEN=$GITHUB_PAT img',
      '--api-key={env:OPENAI_API_KEY}',
      'docker run -p 8080:80 img',
      'ssh -p 22 host',
      '--ssh-key ~/.ssh/id_rsa',
      'API_KEY=<your-api-key>',
      'Remote server without auth: https://mcp.example.com/sse',
      'https://mcp.example.com/sse?page=2&limit=10',
    ];
    for (const t of keep) expect(maskCredentialsInText(t)).toBe(t);
    expect(maskCredentialsDeep({ args: ['run', '-p', '3000:3000', '--token', '${TOKEN}'] }).args)
      .toEqual(['run', '-p', '3000:3000', '--token', '${TOKEN}']);
  });
});

describe('masking: dt14 forms', () => {
  it('masks --header=Authorization and PowerShell $env: assignments', async () => {
    const { maskCredentialsInText } = await import('./serialize.js');
    const out = maskCredentialsInText(`mcp-remote https://x --header=Authorization: Bearer sk-live-abc123def456 ; $env:API_KEY='sk-live-zyx987wvu654' ; $env:GITHUB_TOKEN = "ghp_aaaaaaaaaaaaaaaaaaaa"`);
    expect(out).not.toContain('sk-live-abc123def456');
    expect(out).not.toContain('sk-live-zyx987wvu654');
    expect(out).not.toContain('ghp_aaaaaaaaaaaaaaaaaaaa');
    expect(out).toContain('API_KEY');
  });
});
