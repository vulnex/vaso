import { describe, it, expect } from 'vitest';
import { findArgSecrets, findUrlSecrets, headerArg } from './config-secrets.js';

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
