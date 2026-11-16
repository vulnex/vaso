import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { MAX_SECRETS_PER_ARG, findArgSecrets, maskArgSecrets } from './config-secrets.js';
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

describe('findArgSecrets — options that are not passwords in a script', () => {
  it.each([
    ['mkdir -p $HOME/…', ['-lc', 'mkdir -p "$HOME/.config/my-mcp" && exec node server.js']],
    ['mkdir -p $TMPDIR/…', ['-lc', 'mkdir -p "$TMPDIR/mcp-cache-v2" && exec node server.js']],
    ['mkdir -p ${HOME}/…', ['-lc', 'mkdir -p ${HOME}/Library/Logs/McpServer && exec node server.js']],
    ['mkdir -p a word with digits', ['-c', 'mkdir -p Data2024Q3x && node s.js']],
    ['kubectl exec -p', ['-c', 'kubectl exec -p podName123abc -- ls']],
    ['cp -p', ['-c', 'cp -p Config2024Xy.json /tmp && node s.js']],
    ['pip -p', ['-c', 'pip install -p Pkg2024Abc']],
  ])('%s', (_label, args) => {
    expect(values('bash', args)).toEqual([]);
  });

  it("still reads a client's -p inside a subshell, $(…) or backticks", () => {
    expect(values('sh', ['-c', '(mysql -pSuBs8Xk2Lm9Qz db)'])).toEqual(['SuBs8Xk2Lm9Qz']);
    expect(values('sh', ['-c', 'X=$(mysql -pCsUb8Xk2Lm9Qz -e "select 1" db); node s.js "$X"'])).toEqual(['CsUb8Xk2Lm9Qz']);
    expect(values('sh', ['-c', 'X=`mysql -pBaTk8Xk2Lm9Qz -e x db`; echo $X'])).toEqual(['BaTk8Xk2Lm9Qz']);
  });

  it("reads a server's own -p after a runner's package in a script", () => {
    expect(values('sh', ['-c', 'npx -y @benborla29/mcp-server-mysql -p NsXp8Xk2Lm9Qz'])).toEqual(['NsXp8Xk2Lm9Qz']);
    expect(values('sh', ['-c', 'npx -y -p Xk9mP2qR7vL4wZt8Hn3 mcp-server'])).toEqual([]);
  });
});

describe('findArgSecrets — a -p value that names a path or an id', () => {
  it.each([
    ['$HOME path', ['-p', '$HOME/.config/x']],
    ['~ path', ['-p', '~/Projects/mcp-server/logs']],
    ['project name', ['-y', 'gcp-mcp', '-p', 'myProject2024']],
    ['uuid', ['-y', 'some-mcp', '-p', '3f2a9c4e-1b7d-4e8a-9c2f-6d5e4b3a2c1f']],
  ])('%s', (_label, args) => {
    expect(values('npx', args)).toEqual([]);
  });

  it('a random value is still a password', () => {
    expect(values('npx', ['-y', '@benborla29/mcp-server-mysql', '-p', 'Zq8Lm3Xk7Wv2Nt5'])).toEqual(['Zq8Lm3Xk7Wv2Nt5']);
  });
});

describe('findArgSecrets — Windows and deeper shells', () => {
  it('cmd /c with the command line as one string', () => {
    expect(values('cmd', ['/c', 'mysql -pCmDc8Xk2Lm9Qz db'])).toEqual(['CmDc8Xk2Lm9Qz']);
    expect(values('cmd', ['/c', 'npx -y @modelcontextprotocol/server-postgres postgresql://u:WiNo8Xk2Lm9Qz@h/db'])).toEqual(['WiNo8Xk2Lm9Qz']);
  });

  it('PowerShell -Command with $env: assignments', () => {
    expect(values('pwsh', ['-Command', '$env:PGPASSWORD="PoSh8Xk2Lm9Qz"; psql -h db app'])).toEqual(['PoSh8Xk2Lm9Qz']);
    expect(values('powershell', ['-c', '$env:PGPASSWORD = "PoSh9Xk2Lm9Qz"; psql -h db app'])).toEqual(['PoSh9Xk2Lm9Qz']);
  });

  it('a fourth nested shell', () => {
    expect(values('sh', ['-c', `bash -c "sh -c 'zsh -c \\"mysql -pNeSt4Xk8Lm9Qz db\\"'"`])).toEqual(['NeSt4Xk8Lm9Qz']);
  });
});

describe('findArgSecrets — a script with many credentials', () => {
  const script = (n: number, pad = 0): string => {
    const parts: string[] = [];
    for (let i = 0; i < n; i++) parts.push(`mysql -pPw${String(i).padStart(6, '0')}Xk2Lm9 db`);
    return `${'#'.repeat(pad)}\n${parts.join('; ')}`;
  };

  it('caps the findings per argument and counts the rest', () => {
    const found = findArgSecrets(['-c', script(200)], 'sh');
    expect(found).toHaveLength(MAX_SECRETS_PER_ARG);
    expect(found[found.length - 1].kind).toMatch(/\+150 more in this argument/);
    for (const s of found) {
      expect(s.masked.length).toBeLessThan(400);
      expect(s.masked).not.toMatch(/Pw\d{6}Xk2Lm9/);
    }
  });

  it('masks every credential, not only the reported ones', () => {
    const [, masked] = maskArgSecrets(['-c', script(200)], 'sh');
    expect(masked).not.toMatch(/Pw\d{6}Xk2Lm9/);
    expect(masked.match(/-p\*\*\*/g)).toHaveLength(200);
  });

  it('stays linear on a large script', () => {
    const big = script(20000, 1_500_000);
    const start = Date.now();
    const found = findArgSecrets(['-c', big], 'sh');
    maskArgSecrets(['-c', big], 'sh');
    expect(found).toHaveLength(MAX_SECRETS_PER_ARG);
    expect(Date.now() - start).toBeLessThan(10_000);
  });
});
