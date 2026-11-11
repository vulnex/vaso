import { describe, expect, it } from 'vitest';
import { maskCredentialsDeep, maskCredentialsInLine, maskCredentialsInText } from './serialize.js';

const PW = 'Hunter2Hunter2Zq!';
const both = (s: string) => [maskCredentialsInLine(s), maskCredentialsInText(s)];

describe('report masking — dt21 round 2', () => {
  it('g1-R1: masks values wrapped in escaped quotes inside JSON strings', () => {
    for (const out of both(`{"db":"DB_PASSWORD=\\"${PW}\\" OPENAI_API_KEY=x"}`)) expect(out).toContain('DB_PASSWORD=\\"***\\"');
    for (const out of both(`"run --password=\\"${PW}\\" x"`)) expect(out).toBe('"run --password=\\"***\\" x"');
    for (const out of both(`cmd "password=\\"${PW}\\""`)) expect(out).toBe('cmd "password=\\"***\\""');
    for (const out of both(`{"c":"x --token \\"${PW}\\""}`)) expect(out).not.toContain(PW);
  });

  it('g5-R1: a flag never takes the next flag as its value', () => {
    const v = 'CmdStrTok3nAlphaBravo7788CharlieDelta';
    for (const first of ['--no-auth', '--use-oauth-token', '--token', '--skip-token-check', '--oauth']) {
      for (const out of both(`npx acme ${first} --api-key ${v}`)) expect(out, first).toBe(`npx acme ${first} --api-key ***`);
      expect(maskCredentialsDeep({ args: ['acme', first, '--client-secret', v] }).args, first).toEqual(['acme', first, '--client-secret', '***']);
    }
    expect(maskCredentialsInText(`acme --token --apiKey ${v}`)).toBe('acme --token --apiKey ***');
    expect(maskCredentialsInText(`acme -k --x ${v}`)).toBe(`acme -k --x ${v}`);
  });

  it('g3-R2: a # inside an unquoted value is part of it', () => {
    expect(maskCredentialsInLine('Server "oauth-env": OAUTH_CLIENT_SECRET=Xk9#mP2$...')).toBe('Server "oauth-env": OAUTH_CLIENT_SECRET=Xk9#mP2$...');
    expect(maskCredentialsInLine('client_secret: Xk9#mP2$vL8@Zq7Rt5')).toBe('client_secret: ***');
    expect(maskCredentialsInLine('{"client_secret":Xk9#mP2vL8Zq7Rt5}')).toBe('{"client_secret":***}');
    expect(maskCredentialsInLine('token: abc #comment')).toBe('token: *** #comment');
  });

  it('g3-R3 / g3-R4: -p masks passwords only', () => {
    for (const keep of ['docker run -p ${port}:3000 nginx', 'docker run -p 8080:8080', 'ssh -p 2222 host', 'python3 -m pip install -p 3.11 foo',
      'tar -xzpf a.tgz -p preserve', 'npx -y -p @scope/mcp-server-xyz@1.2.3 mcp-xyz', 'npx -p mcp-xyz@1.2.3 x',
      'mysql -h db -u root -p${process.env.DB_PASS} -e x', 'sshpass -p "$SSHPASS" ssh host', 'Usage: mysql -p<password>']) {
      for (const out of both(keep)) expect(out, keep).toBe(keep);
    }
    expect(maskCredentialsDeep({ args: ['-y', '-p', '@scope/mcp-server-xyz@1.2.3', 'mcp-xyz'] }).args).toEqual(['-y', '-p', '@scope/mcp-server-xyz@1.2.3', 'mcp-xyz']);
    expect(maskCredentialsDeep({ args: ['run', '-p', '${PORT}:80'] }).args).toEqual(['run', '-p', '${PORT}:80']);
    for (const masked of ['sshpass -p i9LE1Ki3ylOjt6o0 ssh', 'mysql -p hunterhunter', 'mysql -uroot -pHq7Zx3Rm9Lw2Np4Kv', 'mysql -p MyS3cret!x', 'x -p Xq9Zr7Lp2Wm4Kd8Vn3Bt6']) {
      for (const out of both(masked)) expect(out, masked).toContain('***');
    }
    expect(maskCredentialsDeep({ args: ['mysql', '-pHunterhunter'] }).args).toEqual(['mysql', '-p***']);
  });

  it('F17: a placeholder word inside a passphrase does not keep it', () => {
    expect(maskCredentialsInLine('"pass_words": "correct your horse qCzGdWmPyagqqr5v",')).toBe('"pass_words": "***",');
    expect(maskCredentialsInLine('password: correct your horse battery staple')).toBe('password: ***');
    for (const keep of ['password: insert your password here', '"api_key": "<your api key>"', 'token: your-token-here', 'password: changeme']) {
      expect(maskCredentialsInLine(keep), keep).toBe(keep);
    }
  });
});
