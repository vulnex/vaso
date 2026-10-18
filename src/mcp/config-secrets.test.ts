import { describe, it, expect } from 'vitest';
import { findArgSecrets, findUrlSecrets } from './config-secrets.js';

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
