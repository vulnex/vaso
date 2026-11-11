import { describe, expect, it } from 'vitest';
import { findArgSecrets, findUrlSecrets, findValueSecrets, headerSecret, isCredentialFlag, maskArgSecrets } from './config-secrets.js';

const V = 'oNZYW2mZp0zVZomHFwUbbYrEqmSM9w';
const found = (args: string[]) => findArgSecrets(args).map(s => s.value);

describe('findArgSecrets — dt21 g3-F2 / g8-F16: flag spellings', () => {
  it('reads camelCase credential flags', () => {
    for (const flag of ['--oauth2Bearer', '--githubToken', '--botToken', '--apiToken', '--secretKey', '--privateKey', '--apiSecret', '--aws-secret-access-key']) {
      expect(isCredentialFlag(flag), flag).toBe(true);
      expect(found(['x', flag, V]), flag).toEqual([V]);
      expect(found(['x', `${flag}=${V}`]), flag).toEqual([V]);
    }
    for (const flag of ['--monkey', '--hotkey', '--bypass', '--tokenizer']) expect(isCredentialFlag(flag), flag).toBe(false);
  });

  it('reads --env=K=V, helm --set and kubectl --from-literal', () => {
    expect(found(['run', `--env=OPENAI_API_KEY=${V}`])).toEqual([V]);
    expect(found(['--set', `auth.password=${V}`])).toEqual([V]);
    expect(found(['--set-string', `redis.auth.token=${V}`])).toEqual([V]);
    expect(found(['create', 'secret', `--from-literal=password=${V}`])).toEqual([V]);
    expect(found(['--set', 'image.tag=v1.2.3-abcdef123456'])).toEqual([]);
  });

  it('reads -p passwords but not ports or packages', () => {
    expect(found(['mysql', '-uroot', `-p${V}`])).toEqual([V]);
    expect(found(['sshpass', '-p', V, 'ssh', 'host'])).toEqual([V]);
    expect(found(['run', '-p', '8080:80', 'img'])).toEqual([]);
    expect(found(['-p', '@modelcontextprotocol/server-github@1.0.0', 'mcp'])).toEqual([]);
    expect(found(['gcc', '-pthread'])).toEqual([]);
  });

  it('reads "--api-key <v>" written as one element', () => {
    expect(found(['x', `--api-key ${V}`])).toEqual([V]);
  });
});

describe('findArgSecrets — dt21 g3-F4: connection strings, headers, cookies', () => {
  it('finds passwords in connection URLs of any scheme', () => {
    for (const url of [`postgresql://admin:${V}@db.example/prod`, `redis://:${V}@cache.example:6379`, `mongodb+srv://u:${V}@cluster0.example.net/?retryWrites=true`, `amqp://guest:${V}@mq.example`]) {
      const s = findArgSecrets(['-y', 'x@1.0.0', url]);
      expect(s.map(x => x.value), url).toEqual([V]);
      expect(s[0].masked).not.toContain(V);
      expect(found(['x', `--connectionString=${url}`]), url).toEqual([V]);
      expect(found(['x', '--connectionString', url]), url).toEqual([V]);
    }
    expect(found(['x', `DATABASE_URL=mysql://app:${V}@db/x`])).toEqual([V]);
    expect(found(['x', 'postgresql://app@db.example/prod', 'postgresql://${USER}:${PASS}@db/x'])).toEqual([]);
  });

  it('finds Password= pairs in connection strings and DSNs', () => {
    expect(found(['x', `--connection-string=Server=db;User Id=sa;Password=${V};`])).toEqual([V]);
    expect(found(['x', '--connection-string', `Server=x;Database=y;User Id=sa;Password=${V};`])).toEqual([V]);
    expect(found(['x', '--dsn', `host=db user=app password=${V} dbname=x`])).toEqual([V]);
    expect(found(['x', 'Server=db;Password=${DB_PASS};'])).toEqual([]);
  });

  it('finds header arguments in every form', () => {
    expect(found(['mcp-remote', 'https://a.example/mcp', `--header=Authorization: Bearer ${V}`])).toEqual([V]);
    expect(found(['mcp-remote', 'https://a.example/mcp', '-H', `X-API-Key: ${V}`])).toEqual([V]);
    expect(found(['x', '--header', `Cookie: session=${V}; theme=dark`])).toEqual([V]);
    expect(found(['x', '--header', `Ocp-Apim-Subscription-Key: ${V}`])).toEqual([V]);
    expect(found(['x', '--header', 'Cookie: theme=dark; lang=en'])).toEqual([]);
  });

  it('masks what it finds, in mcp list / MCP-001 argv', () => {
    const out = maskArgSecrets(['x', `--oauth2Bearer=${V}`, `--env=OPENAI_API_KEY=${V}x`, `postgresql://admin:${V}y@db/prod`]);
    expect(out.join(' ')).not.toContain(V);
    expect(out[3]).toBe('postgresql://admin:***@db/prod');
  });
});

describe('findValueSecrets / findUrlSecrets / headerSecret — dt21', () => {
  it('finds connection-URL and connection-string passwords in env values', () => {
    expect(findValueSecrets(`mysql://app:${V}@db/x`, 'env.DATABASE_URL').map(s => s.value)).toEqual([V]);
    expect(findValueSecrets(`Server=db;Password=${V};`, 'env.CONN').map(s => s.value)).toEqual([V]);
    expect(findValueSecrets('redis://cache:6379/0', 'env.REDIS_URL')).toEqual([]);
    expect(findValueSecrets('debug', 'env.LOG_LEVEL')).toEqual([]);
  });

  it('keeps path heuristics to web URLs', () => {
    expect(findUrlSecrets('postgresql://db.example/Xq7Lk2Pz9Rt4Vw8Ym3Nb6Hc1Jd5Fg0Sa')).toEqual([]);
  });

  it('judges a cookie header', () => {
    expect(headerSecret('Cookie', `session=${V}`)).toMatch(/session cookie/);
    expect(headerSecret('Cookie', 'theme=dark')).toBeUndefined();
  });

  it('reads a base64 secret that starts with / as a secret, not a file (g8-F15)', () => {
    expect(found(['x', '--token', '/Hk4Lm8Np2Qr6St0Uv3Wx7Yz1Ab5Cd9Ef'])).toEqual(['/Hk4Lm8Np2Qr6St0Uv3Wx7Yz1Ab5Cd9Ef']);
    expect(found(['x', '--credentials', '/home/u/.config/gcloud/creds.json'])).toEqual([]);
  });

  it('stays linear on long blank runs in a connection-string-like argument', () => {
    const start = Date.now();
    findArgSecrets(['--x', `a=b${' '.repeat(100_000)}password`, `cookie:${' '.repeat(100_000)}x`]);
    expect(Date.now() - start).toBeLessThan(1000);
  });
});

describe('findArgSecrets — dt21 m4 follow-ups', () => {
  it('reads curl --cookie and a spaced --token = value', () => {
    expect(found(['x', '--cookie', `session=${V}`])).toEqual([V]);
    expect(found(['x', `--token = ${V}`])).toEqual([V]);
    const start = Date.now();
    findArgSecrets([`--x${' '.repeat(100_000)}a b`]);
    expect(Date.now() - start).toBeLessThan(1000);
  });
});
