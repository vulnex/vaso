import { describe, it, expect } from 'vitest';
import { findArgSecrets, findUrlSecrets, headerArg, headerSecret, maskArgSecrets, maskUrlSecrets } from './config-secrets.js';

const GHP = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';
const OPENAI = 'sk-proj-' + 'Zq3xV9mK2pL8nR4tW7yB1cD6fG0hJ5sA';
const SLACK = 'xoxb-' + '123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx';
const AWS = 'AKIA' + 'Z7Q3XK2M9PL4NR8T';
const TELEGRAM = '1234567890:' + 'AAFq3xV9mK2pL8nR4tW7yB1cD6fG0hJ5sAQ';

const noValue = (secrets: ReturnType<typeof findArgSecrets>, value: string) =>
  secrets.every(s => [s.masked, s.location, s.kind].every(t => !t.includes(value.slice(-8)) && !t.includes(value.slice(4, 12))));

describe('findArgSecrets', () => {
  it('finds bare tokens as argv elements', () => {
    for (const token of [GHP, OPENAI, SLACK, AWS]) {
      const found = findArgSecrets(['-y', '@modelcontextprotocol/server-github', token]);
      expect(found).toHaveLength(1);
      expect(found[0].location).toBe('args[2]');
      expect(noValue(found, token)).toBe(true);
    }
  });

  it('finds values after credential flags, split or joined', () => {
    expect(findArgSecrets(['server', '--token', GHP])[0].kind).toMatch(/GitHub PAT after --token/);
    expect(findArgSecrets(['server', '--token', SLACK])[0].masked).toBe('--token ***');
    expect(findArgSecrets(['server', '--api-key=' + OPENAI])[0].kind).toMatch(/OpenAI/);
    // No known prefix, but a random value behind a credential flag
    const generic = findArgSecrets(['server', '--auth-token', 'q8Zr2Lm9Xc4Vb7Nt1Kp3']);
    expect(generic).toHaveLength(1);
    expect(generic[0].masked).toBe('--auth-token ***');
  });

  it('finds env assignments and header arguments', () => {
    expect(findArgSecrets(['run', '-i', '-e', `GITHUB_PERSONAL_ACCESS_TOKEN=${GHP}`, 'ghcr.io/github/github-mcp-server'])).toHaveLength(1);
    expect(findArgSecrets(['run', '-e', 'DB_PASSWORD=Tr0ub4dor-x9Kq2Lm7Vb']).length).toBe(1);
    const header = findArgSecrets(['mcp-remote', 'https://mcp.example.com/sse', '--header', `Authorization: Bearer ${OPENAI}`]);
    expect(header).toHaveLength(1);
    expect(header[0].masked).toBe('Authorization: Bearer ***');
  });

  it('finds secrets in URL arguments', () => {
    const found = findArgSecrets(['mcp-remote', `https://mcp.example.com/sse?api_key=${OPENAI}`]);
    expect(found).toHaveLength(1);
    expect(found[0].masked).toBe('https://mcp.example.com/sse?api_key=***');
  });

  it('treats secret manager references, key file names and profile names as references (dt17 MD-C)', () => {
    for (const ref of [
      'op://Private/GitHub/credential',
      'arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/mcp-AbC123',
      'arn:aws:ssm:eu-west-1:123456789012:parameter/mcp/token',
      'vault:secret/data/mcp#token',
      'ref+vault://secret/mcp#/token',
      'projects/my-project-123/secrets/mcp-token/versions/latest',
      'https://myvault.vault.azure.net/secrets/mcp-token/0123456789abcdef0123456789abcdef',
      'keychain:github-mcp-token1',
      'ENC[AES256_GCM,data:Tr7o=,iv:1=,tag:k=,type:str]',
      'service-account-key.json',
      'production-us-east-2',
    ]) {
      expect(findArgSecrets(['--token', ref]), ref).toEqual([]);
      expect(findArgSecrets(['-e', `GITHUB_TOKEN=${ref}`]), ref).toEqual([]);
      expect(findArgSecrets([`--api-key=${ref}`]), ref).toEqual([]);
    }
    expect(findUrlSecrets('https://mcp.example.com/sse?key=documentation')).toEqual([]);
    // true positives beside them: literal secrets, a passphrase, a password parameter
    expect(findArgSecrets(['--token', GHP])).toHaveLength(1);
    expect(findArgSecrets(['--api-key', 'q7Zp2Lk9Vx4Rt8Mw3Nc6Bh1Jd5Fg0Sa'])).toHaveLength(1);
    expect(findArgSecrets(['--password', 'correct-horse-battery-staple-9'])).toHaveLength(1);
    expect(findArgSecrets(['--token', 'pass:q7Zp2Lk9Vx4Rt8Mw3Nc6Bh1Jd5Fg0Sa'])).toHaveLength(1);
    expect(findArgSecrets(['--token', `op://${GHP}`])).toHaveLength(1);
    expect(findUrlSecrets('https://mcp.example.com/sse?api_key=q7Zp2Lk9Vx4Rt8Mw3Nc6Bh1Jd5Fg0Sa')).toHaveLength(1);
    expect(findUrlSecrets('https://mcp.example.com/sse?password=hunter22')).toHaveLength(1);
  });

  it('stays quiet on references, placeholders, paths and ordinary flags', () => {
    expect(findArgSecrets(['--token', '${GITHUB_TOKEN}'])).toEqual([]);
    expect(findArgSecrets(['--token', '$GITHUB_TOKEN'])).toEqual([]);
    expect(findArgSecrets(['--token', '%GITHUB_TOKEN%'])).toEqual([]);
    expect(findArgSecrets(['--api-key={env:OPENAI_API_KEY}'])).toEqual([]);
    expect(findArgSecrets(['--header', 'Authorization: Bearer ${AUTH_TOKEN}'])).toEqual([]);
    expect(findArgSecrets(['--header', 'Authorization:${AUTH_HEADER}'])).toEqual([]);
    expect(findArgSecrets(['-e', 'GITHUB_TOKEN'])).toEqual([]);
    expect(findArgSecrets(['-e', 'GITHUB_TOKEN=${GITHUB_TOKEN}'])).toEqual([]);
    expect(findArgSecrets(['--token', 'ghp_your_token_here'])).toEqual([]);
    expect(findArgSecrets(['--credentials', '/home/u/.config/gcloud/creds.json'])).toEqual([]);
    expect(findArgSecrets(['--password', 'changeme'])).toEqual([]);
    expect(findArgSecrets(['--token', 'default'])).toEqual([]);
    expect(findArgSecrets(['-y', '@modelcontextprotocol/server-filesystem', '/Users/me/projects'])).toEqual([]);
    expect(findArgSecrets(['--port', '8080', '--transport', 'stdio', 'LOG_LEVEL=debug'])).toEqual([]);
    expect(findArgSecrets(['mcp-remote', 'https://mcp.example.com/sse'])).toEqual([]);
  });
});

describe('findUrlSecrets', () => {
  it('finds userinfo passwords and tokens', () => {
    const pw = findUrlSecrets('https://admin:S3cr3t-Pa55w0rd@mcp.example.com/sse');
    expect(pw).toHaveLength(1);
    expect(pw[0].masked).toBe('https://admin:***@mcp.example.com/sse');
    expect(findUrlSecrets(`https://${GHP}@mcp.example.com/mcp`)[0].kind).toMatch(/GitHub PAT/);
  });

  it('finds credential query parameters and token path segments', () => {
    expect(findUrlSecrets('https://mcp.example.com/mcp?token=a8Kq2Lm7Vb3Xc9Zr')[0].masked).toBe('https://mcp.example.com/mcp?token=***');
    const tg = findUrlSecrets(`https://api.telegram.org/bot${TELEGRAM}/sendMessage`);
    expect(tg).toHaveLength(1);
    expect(tg[0].masked).toBe('https://api.telegram.org/bot***/sendMessage');
    expect(findUrlSecrets(`https://mcp.example.com/${OPENAI}/sse`)).toHaveLength(1);
  });

  it('stays quiet on references and credential-free URLs', () => {
    expect(findUrlSecrets('https://${MCP_USER}:${MCP_PASS}@mcp.example.com/sse')).toEqual([]);
    expect(findUrlSecrets('https://mcp.example.com/mcp?api_key=${API_KEY}')).toEqual([]);
    expect(findUrlSecrets('https://mcp.example.com/mcp?key=%API_KEY%')).toEqual([]);
    expect(findUrlSecrets('https://mcp.example.com/mcp?format=json&page=2')).toEqual([]);
    expect(findUrlSecrets('https://mcp.example.com/sse')).toEqual([]);
    expect(findUrlSecrets('https://git@github.com/org/repo')).toEqual([]);
    expect(findUrlSecrets('https://mcp.example.com/mcp/550e8400-e29b-41d4-a716-446655440000')).toEqual([]);
  });
});

describe('token prefixes inside words', () => {
  it('ignores a prefix that continues a word', () => {
    expect(findArgSecrets(['/opt/servers/task-runnerserverabcdefghijklmnop/index.js'])).toEqual([]);
    expect(findArgSecrets(['@acme/desk-notificationsmcpserverabcdef'])).toEqual([]);
  });
});

describe('headerArg (linear header-argument parsing, dt17)', () => {
  // The regex it replaces, kept as the reference for what a header argument is
  const OLD = /^\s*((?:proxy-)?authorization|x-[\w-]*(?:key|token|secret|auth)[\w-]*|api[_-]?key)\s*:\s*(?:(?:bearer|basic|token|bot)\s+)?(.+?)\s*$/i;
  const reference = (s: string): [string, string] | undefined => {
    const m = OLD.exec(s);
    return m ? [m[1], m[2]] : undefined;
  };

  it('captures exactly what the old regex captured', () => {
    const pieces = ['Authorization', 'x-api-key', 'X-Auth', 'api_key', 'proxy-authorization', 'x-', 'key', ':', ' ', '  ', '\t', '\n', '\r', '\u2028', 'Bearer', 'bearer ', 'bot', 'token', 'sk-abc123', 'v', '-', 'é'];
    let seed = 7;
    const rand = (n: number) => { seed = (seed * 1103515245 + 12345) % 2 ** 31; return (seed >>> 16) % n; };
    let matched = 0;
    for (let i = 0; i < 20_000; i++) {
      // [whitespace] name [whitespace] ':' then a random tail
      let s = (rand(4) === 0 ? pieces[8 + rand(5)] : '') + pieces[rand(5)] + (rand(4) === 0 ? ' ' : '') + (rand(5) === 0 ? '' : ':');
      const len = rand(8);
      // line breaks in half the tails only: most tails holding one fail both ways
      const breaks = rand(2) === 0;
      for (let j = 0; j < len; j++) {
        const piece = pieces[rand(pieces.length)];
        s += breaks || !/[\n\r\u2028]/.test(piece) ? piece : 'q';
      }
      const want = reference(s);
      if (want) matched++;
      expect(headerArg(s), JSON.stringify(s)).toEqual(want);
    }
    expect(matched).toBeGreaterThan(1000);
    for (const s of ['Authorization: Bearer sk-1', 'authorization:   ', 'authorization: bearer   ', ' x-api-key :tok  \n ', 'authorization: a\nb', 'Authorization:\nabc', 'authorization: bot\t\tx  ', 'authorization: \n ']) {
      expect(headerArg(s), JSON.stringify(s)).toEqual(reference(s));
    }
  });

  it('is linear on long name runs and long whitespace inside the value', () => {
    for (const arg of [` x-${'key'.repeat(70_000)}`, `authorization: x${' '.repeat(100_000)}x`, `authorization:${' '.repeat(100_000)}\na\nb`, `x-${'-'.repeat(100_000)}`]) {
      const start = Date.now();
      findArgSecrets(['--header', arg]);
      expect(Date.now() - start, arg.slice(0, 20)).toBeLessThan(1000);
    }
  });

  it('still masks a token in a header argument', () => {
    const r = findArgSecrets(['--header', `X-Api-Key: ${OPENAI}`]);
    expect(r).toHaveLength(1);
    expect(noValue(r, OPENAI)).toBe(true);
  });
});

// dt20 g3-F6: credentials in the URL path or fragment were neither found nor masked
describe('findUrlSecrets: secret paths and fragments', () => {
  const ZAPIER_KEY = 'sk-ak-' + 'Zq7XyR9kLmN3pQ8sT2vW5bC6dF1gH4jK';
  const ZAPIER_S = 'NjQ4ZTk2YmUtZmY3Ny00ZDQ5LWE1ZjMtYjc2ZTkzN2E2NTRhOjE2MzQ1Njc4OQ==';

  it.each([
    [`https://actions.zapier.com/mcp/${ZAPIER_KEY}/sse`, ZAPIER_KEY, /Zapier/],
    [`https://mcp.zapier.com/api/mcp/s/${ZAPIER_S}/mcp`, ZAPIER_S, /Zapier MCP server secret in URL path/],
    ['https://hooks.slack.com/services/T01ABCDEF/B02GHIJKL/Zq8xL2vN7pR4tW9yB3dF6hJ1', 'T01ABCDEF/B02GHIJKL/Zq8xL2vN7pR4tW9yB3dF6hJ1', /Slack webhook/],
    ['https://discord.com/api/webhooks/123456789012345678/Ab3De5Fg7Hj9Kl1Mn3Pq5Rs7Tu9Vw1Xy', 'Ab3De5Fg7Hj9Kl1Mn3Pq5Rs7Tu9Vw1Xy', /Discord/],
    ['https://mcp.example.com/mcp#access_token=7a9f3c1e5b2d4f6a8c0e1b3d5f7a9c2e', '7a9f3c1e5b2d4f6a8c0e1b3d5f7a9c2e', /fragment "access_token"/],
    ['https://mcp.pipedream.example/v1/Qm8xR2vN7pL4tW9yB3dF6hJ1kZ5n/sse', 'Qm8xR2vN7pL4tW9yB3dF6hJ1kZ5n', /random token in URL path/],
    // g8 re-verify shapes
    ['https://mcp.example.com/k/29a95249f512c17b8ed411fa644d35db41d94e5e/sse', '29a95249f512c17b8ed411fa644d35db41d94e5e', /hex token in MCP\/webhook URL path/],
    ['https://mcp.example.com/k/9FSUuErsEz5jhy0I9lO7.F3vlfFrGYJ3GxeYYXwSL/sse', '9FSUuErsEz5jhy0I9lO7.F3vlfFrGYJ3GxeYYXwSL', /random token/],
    ['https://mcp.example.com/k/QcWtxJTQr1FqXSTs98vP~lL2aEJXquQrDs0GPRZww/sse', 'QcWtxJTQr1FqXSTs98vP~lL2aEJXquQrDs0GPRZww', /random token/],
    ['https://mcp.example.com/k/rPwV81Aw71l33SCx9vHj%2FHkm1x72EsSfUQUAkNX7L/sse', 'rPwV81Aw71l33SCx9vHj%2FHkm1x72EsSfUQUAkNX7L', /random token/],
    ['https://mcp.example.com/u/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxN99mhWp708.DwGw5HqXDgLVXZx3scB8fnvGNx6jvr/sse', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxN99mhWp708.DwGw5HqXDgLVXZx3scB8fnvGNx6jvr', /JWT/],
    ['https://hooks.zapier.com/hooks/catch/1234567/70t9rbmk/', '70t9rbmk', /Zapier webhook key/],
    ['https://api.telegram.org/bot123456789:LCNPloWRlOTcEokd5ihu9lEmJcADwyQNeLn/sendMessage', '123456789:LCNPloWRlOTcEokd5ihu9lEmJcADwyQNeLn', /Telegram/],
    ['https://x.example.com/p;jsessionid=guK6NIjuO45KyBBoFsETyy926kMMqVtF', 'guK6NIjuO45KyBBoFsETyy926kMMqVtF', /jsessionid/],
  ])('finds and masks the credential in %s', (url, value, kind) => {
    const found = findUrlSecrets(url);
    expect(found).toHaveLength(1);
    expect(found[0].kind).toMatch(kind);
    expect(found[0].value).toBe(value);
    expect(found[0].masked).not.toContain(value);
    expect(maskUrlSecrets(url)).toBe(url.replace(value, '***'));
  });

  it.each([
    'https://mcp.example.com/v1/projects/3f9a1c7e-2b8d-4f6a-0c5e-9b1d7f3a8c2e/mcp',
    'https://mcp.example.com/repos/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b/sse',
    'https://mcp.example.com/My-Project-2024-Server-Name/mcp',
    'https://mcp.zapier.com/api/v1/connect',
    'https://docs.example.com/guide#section-authentication',
    'https://mcp.example.com/mcp#token=${MCP_TOKEN}',
    // document IDs on content hosts, commit SHAs and digests, names
    'https://docs.google.com/document/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/edit',
    'https://drive.google.com/file/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/view',
    'https://www.figma.com/design/Ab3De5Fg7Hj9Kl1Mn3Pq5Rs/Design',
    'https://www.notion.so/My-Page-8a7c2b1e1234abc9def0123456789abX',
    'https://github.com/vulnex/vaso/commit/8fa17d3e1b2c4d5e6f708192a3b4c5d6e7f80912',
    'https://mcp.example.com/commit/8fa17d3e1b2c4d5e6f708192a3b4c5d6e7f80912',
    'https://cdn.example.com/blobs/29a95249f512c17b8ed411fa644d35db41d94e5e',
    'https://cdn.jsdelivr.net/npm/Package-Name_Version2Beta3Gamma4/dist/index.js',
    'https://en.wikipedia.org/wiki/Model_Context_Protocol_Specification2025',
  ])('leaves %s alone', (url) => {
    expect(findUrlSecrets(url)).toEqual([]);
    expect(maskUrlSecrets(url)).toBe(url);
  });

  it('masks URL arguments too', () => {
    const args = ['-y', 'slack-hook-mcp@1.0.0', 'https://hooks.slack.com/services/T00000000/B0123456789ABCDEFGHIJKLMNOP'];
    expect(maskArgSecrets(args)).toEqual(['-y', 'slack-hook-mcp@1.0.0', 'https://hooks.slack.com/services/***']);
  });
});

describe('headerSecret', () => {
  it.each([
    ['X-Api-Key', 'wJalrXUtnFEMI-K7MDENG-bPxRfiCYzz9a8b7c6d'],
    ['Authorization', 'Bearer abcdef0123456789xyz'],
    ['Authorization', `Bearer ${OPENAI}`],
    ['X-Auth-Token', 'q8Zr2Lm9Xc4Vb7Nt1Kp3'],
  ])('flags %s: %s', (name, value) => {
    expect(headerSecret(name, value)).toBeDefined();
  });

  it.each([
    ['Authorization', 'Bearer ${API_TOKEN}'],
    ['X-Api-Key', '$MY_KEY'],
    ['X-Api-Key', '<your-api-key>'],
    ['Accept', 'application/json'],
    ['X-Request-Id', 'q8Zr2Lm9Xc4Vb7Nt1Kp3'],
  ])('leaves %s: %s alone', (name, value) => {
    expect(headerSecret(name, value)).toBeUndefined();
  });
});

describe('dt20 re-verify 4: hex IDs in MCP URL paths', () => {
  it('flags a hex key in the key position but not resource IDs or commit SHAs', () => {
    const key = 'f3c9a1b7e5d2468a9b0c1d2e3f405162';
    expect(findUrlSecrets(`https://mcp.example.com/${key}/sse`).length).toBeGreaterThan(0);
    expect(findUrlSecrets(`https://hooks.example.com/hooks/${key}`).length).toBeGreaterThan(0);
    expect(findUrlSecrets(`https://api.example.com/mcp/projects/5f2b8c1e9a4d4e6fb1c27d8e9f0a1b2c/sse`)).toEqual([]);
    expect(findUrlSecrets(`https://mcp.example.com/raw/${'a1b2c3d4e5'.repeat(4)}/mcp`)).toEqual([]);
  });
});

describe('dt20 re-verify 4: credentials in inline JSON arguments', () => {
  it('finds and masks a credential-named pair inside a JSON argument', () => {
    const args = ['srv.js', '--config', '{"token":"Wq2Er3Ty4Ui5Op6As7Df8Gh9","region":"eu-west-1"}'];
    expect(findArgSecrets(args).map(s => s.value)).toEqual(['Wq2Er3Ty4Ui5Op6As7Df8Gh9']);
    expect(maskArgSecrets(args)[2]).toBe('{"token":"***","region":"eu-west-1"}');
    expect(findArgSecrets(['--config', '{"token_type":"bearer_token_value","password_hash":"$2b$12$abcdefghijkl"}'])).toEqual([]);
  });
});

describe('dt20 re-verify 5: Teams incoming webhooks', () => {
  it('finds and masks the IncomingWebhook key', () => {
    const key = '6c90b94f1a2b3c4d5e6f7a8b9c0d5706';
    const url = `https://acme.webhook.office.com/webhookb2/11111111-2222-3333-4444-555555555555@66666666-7777-8888-9999-000000000000/IncomingWebhook/${key}/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`;
    expect(findUrlSecrets(url).map(s => s.value)).toContain(key);
    expect(maskUrlSecrets(url)).not.toContain(key);
  });
});

describe('dt20 re-verify 5: escaped inline JSON in a shell argument', () => {
  it('finds and masks a credential inside backslash-escaped JSON', () => {
    const args = ['-c', 'run --cfg "{\\"apiKey\\":\\"Rt5Yu6Io7Pa8Sd9Fg0Hj1Kl2\\"}"'];
    expect(findArgSecrets(args).map(s => s.value)).toEqual(['Rt5Yu6Io7Pa8Sd9Fg0Hj1Kl2']);
    expect(maskArgSecrets(args)[1]).not.toContain('Rt5Yu6Io7Pa8');
  });
});
