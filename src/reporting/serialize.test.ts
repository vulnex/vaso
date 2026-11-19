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
    // its length only: no character of the value (a prefix was half of a short secret)
    expect(server.env).toEqual({ GITHUB_TOKEN: `<literal, ${token.length} chars>`, DEBUG: '***' });
    expect(server.headers.Authorization).toBe(`<literal, ${SECRET.length + 7} chars>`);
  });

  it('masks every credential on a quoted one-line JSON snippet', () => {
    const nv = 'nvapi-PLANTEDNMKEY0123456789abcdefghijklmnop';
    const custom = 'CUSTOMsecretVALUE0123456789xyzABC';
    const out = toReportJson({ evidence: [{ file: '/h/.nemoclaw/credentials.json', snippet: `{"NVIDIA_API_KEY":"${nv}","apiKey":"${custom}","model":"llama"}` }] });
    expect(out).not.toContain(nv.slice(0, 16));
    expect(out).not.toContain(custom.slice(0, 16));
    expect(out).toContain('"model\\":\\"llama');
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

  it('leaves source assignments of code alone, masks secret-shaped values (dt17)', async () => {
    const { maskCredentialsInText, maskCredentialsInLine } = await import('./serialize.js');
    for (const line of ['code = notify(message)', 'token = headers["x-token"]', 'password = args.password', 'session = requests.Session()',
      'api_key = None', 'CODE=200', 'if code == 200:']) {
      expect(maskCredentialsInText(line), line).toBe(line);
    }
    expect(maskCredentialsInLine('    api_key = os.environ.get("KEY")')).toBe('    api_key = os.environ.get("KEY")');
    // true positives: literals, env lines, bare words in INI, a JWT
    expect(maskCredentialsInText('token = "q7Zp2Lk9Vx4Rt8Mw3Nc6"')).toBe('token = ***');
    expect(maskCredentialsInText('API_TOKEN=q7Zp2Lk9Vx4Rt8Mw3Nc6')).toBe('API_TOKEN=***');
    expect(maskCredentialsInText('password = hunter2')).toBe('password = ***');
    expect(maskCredentialsInText('PASSWORD=ab(cd12!')).toBe('PASSWORD=***');
    expect(maskCredentialsInText('session = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'))
      .not.toContain('dozjgNryP4J3jVmNHl0w5N');
    expect(maskCredentialsInLine('password = get_secret')).toBe('password = ***');
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
    ['npx pkg --token TOK0013 --key=KEY0014 --pat=PAT0015 -p PW0016q9Zr7Lp2Wm4Kd', 'TOK0013'],
    ['npx pkg --token TOK0013 --key=KEY0014 --pat=PAT0015 -p PW0016q9Zr7Lp2Wm4Kd', 'KEY0014'],
    ['npx pkg --token TOK0013 --key=KEY0014 --pat=PAT0015 -p PW0016q9Zr7Lp2Wm4Kd', 'PAT0015'],
    ['npx pkg --token TOK0013 --key=KEY0014 --pat=PAT0015 -p PW0016q9Zr7Lp2Wm4Kd', 'PW0016'],
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
    [['mysql', '-pPW0105'], 'PW0105'],
    [['sshpass', '-p', 'PW0107'], 'PW0107'],
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

describe('masking: bare well-known tokens and --auth/--bearer values', () => {
  const GHP = 'ghp_Q7rT2mZ9kLp4Wn8Vx3Bc6Hd1Fj5Gs0Ae2Ry7';
  const PROJ = 'sk-proj-Q7rT2mZ9kLp4Wn8Vx3Bc6Hd1Fj5Gs0Ae';
  const XOXB = 'xoxb-1234567890-Q7rT2mZ9kLp4SLK8';
  const AKIA = 'AKIAQ7RT2MZ9KLP4WN12';

  it('masks bare tokens in argv and text, keeping the rest readable', async () => {
    const { toReportJson, maskCredentialsInText } = await import('./serialize.js');
    const json = toReportJson({ servers: [
      { command: 'npx', args: ['-y', 'pkg@1.0.0', GHP] },
      { command: 'npx', args: ['-y', 'pkg@1.0.0', PROJ] },
      { command: 'node', args: ['srv.js', XOXB] },
      { command: 'uvx', args: ['pkg==1.0', AKIA] },
      { command: 'npx', args: ['-y', 'pkg@1.0.0', '--auth', 'Q7rT2mZ9kLp4AUTH17'] },
      { command: 'npx', args: ['-y', 'pkg@1.0.0', '--bearer', 'Q7rT2mZ9kLp4BEAR18'] },
    ] });
    for (const secret of [GHP, PROJ, XOXB, AKIA, 'Q7rT2mZ9kLp4AUTH17', 'Q7rT2mZ9kLp4BEAR18']) expect(json).not.toContain(secret);
    expect(json).toContain('pkg@1.0.0');
    expect(json).toContain('"--auth"');
    expect(maskCredentialsInText(`npx pkg ${GHP} --bearer=Q7rT2mZ9kLp4BEAR18`)).toBe('npx pkg *** --bearer=***');
  });

  it('keeps placeholders, references and redacted forms', async () => {
    const { maskCredentialsInText } = await import('./serialize.js');
    for (const keep of ['ghp_your_token_here', 'AKIAIOSFODNN7EXAMPLE', 'sk-ant-...', 'sk-a...wxyz', '--auth ${API_TOKEN}', '--bearer $TOKEN']) {
      expect(maskCredentialsInText(keep)).toBe(keep);
    }
  });
});

describe('masking cost (dt15 P2/P8)', () => {
  it('trims a URL tail of thousands of brackets in linear time, with the same result', async () => {
    const { maskCredentialsInText } = await import('./serialize.js');
    const start = Date.now();
    const out = maskCredentialsInText(`see https://example.com/a${')'.repeat(100_000)}`);
    expect(Date.now() - start).toBeLessThan(1000);
    expect(out).toBe(`see https://example.com/a${')'.repeat(100_000)}`);
    // trailing punctuation is still trimmed before masking; paired brackets are kept
    const paired = maskCredentialsInText('https://example.com/wiki/A_(b)?token=abc123def456),');
    expect(paired).toContain('A_(b)');
    expect(paired).not.toContain('abc123def456');
    expect(paired.endsWith('),')).toBe(true);
    const quoted = maskCredentialsInText("'https://u:hunter2pass@example.com/'");
    expect(quoted).not.toContain('hunter2pass');
    expect(quoted.endsWith("/'")).toBe(true);
  });

  it('matches x-…key… header names in linear time and still masks them', async () => {
    const { maskCredentialsInText } = await import('./serialize.js');
    const start = Date.now();
    maskCredentialsInText(` x-${'key'.repeat(70_000)}`);
    maskCredentialsInText(` x-${'a'.repeat(200_000)}: v`);
    expect(Date.now() - start).toBeLessThan(1000);
    expect(maskCredentialsInText('X-Goog-Api-Key: AIzaFAKEFAKE123')).not.toContain('AIzaFAKEFAKE123');
    expect(maskCredentialsInText('x-session-id: s3cr3tvalue99')).not.toContain('s3cr3tvalue99');
    expect(maskCredentialsInText('x-request-id: 1234abcd')).toContain('1234abcd');
  });
});

describe('masking: no token tail stays readable (dt16)', () => {
  it('masks every segment of a Slack token and the tail of a longer token', async () => {
    const { maskCredentialsInText } = await import('./serialize.js');
    const slack = 'xoxb-1234567890-0987654321-Q7rT2mZ9kLp4SLK8tail';
    const out = maskCredentialsInText(`node srv.js ${slack} --verbose`);
    expect(out).not.toContain('Q7rT2mZ9kLp4SLK8tail');
    expect(out).not.toContain('0987654321');
    expect(out).toBe('node srv.js *** --verbose');
    const long = `ghp_${'A1b2C3d4E5'.repeat(4)}`;
    expect(maskCredentialsInText(`token ${long}.`)).toBe('token ***.');
  });
});

describe('masking: nested one-line JSON, quoted headers, truncated values (dt20)', () => {
  const S = 'CUSTOMsecretVALUE123456789';

  it('checks every key of a nested object, not just the outer one (g8-F1, g5-F1)', async () => {
    const { maskCredentialsInLine } = await import('./serialize.js');
    expect(maskCredentialsInLine(`{"providers":{"custom":{"apiKey":"${S}"}}}`)).toBe('{"providers":{"custom":{"apiKey":"***"}}}');
    expect(maskCredentialsInLine(`{"env":{"ANTHROPIC_AUTH_TOKEN":"${S}","HTTPS_PROXY":"http://91.92.242.30:8080"}}`))
      .toBe('{"env":{"ANTHROPIC_AUTH_TOKEN":"***","HTTPS_PROXY":"http://91.92.242.30:8080"}}');
    expect(maskCredentialsInLine(`{"gateway":{"auth":{"token":"${S}"}}}`)).not.toContain(S);
    expect(maskCredentialsInLine(`servers: [{"name":"a","env":{"GITHUB_TOKEN":"${S}"}}]`)).not.toContain(S);
  });

  it('masks JSON and TOML Authorization headers (g8-F1)', async () => {
    const { maskCredentialsInLine, maskCredentialsInText } = await import('./serialize.js');
    expect(maskCredentialsInLine(`fetch(u, {headers: {"Authorization": "Bearer ${S}"}})`)).toContain('"Authorization": "Bearer ***"');
    expect(maskCredentialsInText(`"Authorization" = "Bearer ${S}"`)).toBe('"Authorization" = "Bearer ***"');
    expect(maskCredentialsInText(`'x-api-key': '${S}'`)).not.toContain(S);
  });

  it('masks a value cut by snippet truncation (g8-F2)', async () => {
    const { maskCredentialsInLine } = await import('./serialize.js');
    const { redactSecretsInLine, truncateSnippet } = await import('../core/patterns.js');
    const pw = 'Zp9Yx8Wv7Ut6Sr5Qp4On3Ml2Kj1Ih0Gf9Ed8Cb7Aa6Ee5';
    const line = `{"note":"sk-proj-${'Q7rT2mZ9kLp4'.repeat(3)}","db_password":"${pw}"}`;
    const out = maskCredentialsInLine(redactSecretsInLine(line));
    expect(out).not.toContain(pw.slice(0, 6));
    expect(out).toContain('"db_password":"***');
    expect(maskCredentialsInLine(truncateSnippet(`const password = "${pw}${pw}${pw}"`))).not.toContain(pw.slice(0, 6));
  });

  it('masks YAML anchors/tags/flow maps, multi-word values, escaped quotes, TOML triple quotes and more names (g8-F4)', async () => {
    const { maskCredentialsInLine } = await import('./serialize.js');
    for (const line of [
      `token: &tok ${S}`, `token: !!str ${S}`, `creds: {token: ${S}, user: bob}`, `password: correct horse ${S}`,
      `password: abc#${S}`, `password: abc,${S}`, `"password":"ab\\"${S}"`, `password = """${S}"""`,
      `clientKey: ${S}`, `accessKey: ${S}`, `encryptionKey: ${S}`, `passphrase: ${S}`,
      '"id": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV"',
      `"cert": "-----BEGIN PRIVATE KEY-----\\nMIIEv${S}\\n-----END PRIVATE KEY-----"`,
    ]) {
      const out = maskCredentialsInLine(line);
      expect(out, line).not.toContain(S);
      expect(out, line).not.toContain('SflKxwRJSMeKKF2QT4fw');
    }
    expect(maskCredentialsInLine(`password: ${S} # rotated monthly`)).toBe('password: *** # rotated monthly');
    expect(maskCredentialsInLine(`list_tokens: [${S}, \${X}]`)).toBe('list_tokens: [***, ${X}]');
    expect(maskCredentialsInLine(`{"api_keys":["${S}"],"scopes":["read"]}`)).toBe('{"api_keys":["***"],"scopes":["read"]}');
    expect(maskCredentialsInLine('  0OGr4hTxoF54Fzbka8FRCztUjAwyuh1vauWv1zh87mTa5Vsqxezy3Lex7BWr2drg')).toBe('  ***');
  });

  it('leaves settings named after credentials readable', async () => {
    const { maskCredentialsInLine } = await import('./serialize.js');
    for (const line of ['max_tokens: 4096', '"maxTokens": 10', 'tokens_per_minute: 100', 'tokenizer: cl100k_base',
      'passwordPolicy: strict', 'sessionTimeout: 30', 'token: ${TOKEN}', 'password = getpass("x")']) {
      expect(maskCredentialsInLine(line)).toBe(line);
    }
  });
});

describe('snippet length after masking', () => {
  it('cuts a snippet masking lengthened past MAX_SNIPPET, after masking', async () => {
    const { maskCredentialsDeep } = await import('./serialize.js');
    const { MAX_SNIPPET } = await import('../core/patterns.js');
    // `"token":"b",` masks to `"token":"***",`: 300 characters become 350
    const snippet = `{${'"token":"b",'.repeat(24)}"x":1}`;
    expect(snippet.length).toBeLessThanOrEqual(MAX_SNIPPET);
    for (const out of [
      maskCredentialsDeep({ evidence: [{ file: '/f', snippet }] }).evidence[0].snippet,
      JSON.parse(toReportJson({ evidence: [{ file: '/f', snippet }] })).evidence[0].snippet as string,
    ]) {
      expect(out.length).toBeLessThanOrEqual(MAX_SNIPPET + 4);
      expect(out.endsWith(' ...')).toBe(true);
      expect(out).not.toContain('"b"');
    }
  });

  it('leaves a snippet the engine already cut as it is', async () => {
    const { maskCredentialsDeep } = await import('./serialize.js');
    const { MAX_SNIPPET, truncateSnippet } = await import('../core/patterns.js');
    const cut = truncateSnippet('const a = 1; '.repeat(40), MAX_SNIPPET);
    expect(maskCredentialsDeep({ snippet: cut }).snippet).toBe(cut);
  });
});
