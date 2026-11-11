import { describe, expect, it } from 'vitest';
import { maskCredentialsDeep, maskCredentialsInLine, maskCredentialsInText, toReportJson } from './serialize.js';

const leaks = (out: string, secret: string) => out.includes(secret.slice(0, 12)) || out.includes(secret.slice(-10));

describe('report masking — dt21 g8-F15: secrets that start like a path', () => {
  const b64 = ['/Xq7Lk2Pz9Rt4Vw8Ym3Nb6Hc1Jd5Fg0Sa+Ke', '/Mn4Bv7Cx1Zl9Kj3Hg6Fd2Sa8Qw5Er0Ty', './Hk4Lm8Np2Qr6St0Uv3Wx7Yz1Ab5Cd9Ef', '~/Gh5Ij9Kl3Mn7Op1Qr4St8Uv2Wx6Yz0Ab', '/K7MDENG/bPxRfiCYq9Zr2Lm7Vb3Xc9Zr2Lm7V'];
  it('masks a base64 secret whatever it starts with', () => {
    for (const s of b64) {
      const line = `{"env":{"ANTHROPIC_AUTH_TOKEN":"${s}","DB_PASSWORD":"${s}"}}`;
      expect(leaks(maskCredentialsInLine(line), s), s).toBe(false);
      expect(leaks(maskCredentialsInText(`--token ${s}`), s), s).toBe(false);
      expect(leaks(JSON.stringify(maskCredentialsDeep({ args: ['--token', s], env: { GITHUB_TOKEN: s } })), s), s).toBe(false);
    }
  });

  it('keeps real paths readable', () => {
    for (const p of ['~/.ssh/id_rsa', '/home/u/.config/gcloud/creds.json', './secrets/token.txt', '/Users/me/.keys/Xq7Lk2Pz9Rt4Vw8Y.pem', 'C:\\Users\\me\\key.pem', '/run/secrets/db_password']) {
      expect(maskCredentialsInText(`--ssh-key ${p}`)).toBe(`--ssh-key ${p}`);
      expect(maskCredentialsInLine(`password_file: ${p}`)).toBe(`password_file: ${p}`);
    }
  });
});

describe('report masking — dt21 g8-F16: formats, names and flags the checks know', () => {
  it('masks every token format a check reports, and common vendor formats', () => {
    const tokens = [
      'gsk_' + 'Ab3dE5gH7jK9mN1pQ3sT5vX7z',
      'hf_' + 'Ab3dE5gH7jK9mN1pQ3sT5vX7z',
      'xai-' + 'Ab3dE5gH7jK9mN1pQ3sT5vX7zAb3dE5gH7',
      'sk-ak-' + 'Ab3dE5gH7jK9mN1pQ3sT5vX7z',
      'sk-lf-' + '0A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5D',
      'xoxe-' + '1-Ab3dE5gH7jK9mN1pQ3sT5',
      'pat' + 'Ab3dE5gH7jK9mN.' + 'a'.repeat(32) + '0123456789abcdef'.repeat(2),
      'sk_live_' + 'Ab3dE5gH7jK9mN1pQ3sT5',
      'SG.' + 'Ab3dE5gH7jK9mN1pQ3sT' + '.' + 'Ab3dE5gH7jK9mN1pQ3sTvX',
      'npm_' + 'Ab3dE5gH7jK9mN1pQ3sT5vX7zAb3dE5gH7jK9',
      'dop_v1_' + '0123456789abcdef'.repeat(4),
      'ya29.' + 'Ab3dE5gH7jK9mN1pQ3sT5',
      '0x' + '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318',
    ];
    for (const t of tokens) {
      expect(leaks(maskCredentialsInLine(`{"NOTE_0":"${t}","HTTPS_PROXY":"http://91.92.242.30:8080"}`), t), t).toBe(false);
      expect(leaks(maskCredentialsInText(`see ${t} here`), t), t).toBe(false);
    }
    expect(maskCredentialsInText('https://x.example/api?pk=0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318')).not.toContain('4c0883a6');
  });

  it('treats camelCase …Key names, dashed vendor headers and AccountKey= as secret names', () => {
    const v = 'Qz8Wx3Ec7Rv1Tb5Yn9Um2Ik6Ol4Pa0Sd';
    for (const name of ['appKey', 'deployKey', 'writeKey', 'licenseKey', 'hmacKey', 'authKey', 'serviceKey', 'privKey', 'webhookKey', 'creds', 'pin', 'Ocp-Apim-Subscription-Key']) {
      expect(maskCredentialsInLine(`{"${name}":"${v}"}`), name).toBe(`{"${name}":"***"}`);
    }
    expect(maskCredentialsInText(`Ocp-Apim-Subscription-Key: ${v}`)).toBe('Ocp-Apim-Subscription-Key: ***');
    expect(maskCredentialsInText(`DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=${v}==;EndpointSuffix=core.windows.net`)).not.toContain(v.slice(0, 8));
    // a YAML key that only looks like a header is not one
    expect(maskCredentialsInLine('cache-key: deps-v3')).toBe('cache-key: deps-v3');
  });

  it('masks argv flags in any spelling', () => {
    const v = '3Tz85pkNGcVx2RHLKXSf3wh34LxC';
    for (const text of [`--apiToken ${v}`, `--apiToken=${v}`, `--botToken ${v}`, `--secretKey ${v}`, `--apiSecret ${v}`, `--privateKey ${v}`,
      `--githubToken ${v}`, `--oauth2Bearer=${v}`, `--from-literal=password=${v}`, `--set auth.password=${v}`, `--set-string redis.auth.token=${v}`,
      `--env=OPENAI_API_KEY=${v}`, `mysql -uroot -p${v}`, `--token = ${v}`]) {
      expect(leaks(maskCredentialsInText(text), v), text).toBe(false);
    }
    const argv = maskCredentialsDeep({ args: ['/opt/srv/index.js', '--apiToken', v, '--botToken', v + 'x', 'mysql', '-uroot', '-pHunterHunterHunter'] }).args;
    expect(argv).toEqual(['/opt/srv/index.js', '--apiToken', '***', '--botToken', '***', 'mysql', '-uroot', '-p***']);
    expect(maskCredentialsInText('--token = abc123XYZ987qwe')).toBe('--token = ***');
  });

  it('leaves compiler flags, ports and lowercase compounds alone', () => {
    for (const text of ['gcc -pthread -pedantic main.c', 'docker run -p8080:80 img', '--monkey banana99', '--port 8080']) {
      expect(maskCredentialsInText(text)).toBe(text);
    }
  });
});

describe('report masking — dt21 g8-F17 / g3-F3 / g7-L4: cut and command-line values', () => {
  it('masks a password a snippet cut before its @', () => {
    expect(maskCredentialsInLine('fetch("https://u:lz2MPKgcjnCqaXNv')).toBe('fetch("https://u:***');
    expect(maskCredentialsInLine('fetch("https://u:lz2MPKgcjnCqaXNv ...')).toBe('fetch("https://u:*** ...');
    expect(maskCredentialsInText('see http://localhost:8080/x')).toBe('see http://localhost:8080/x');
    expect(maskCredentialsInText('see http://[::1]:8080/x')).toBe('see http://[::1]:8080/x');
  });

  it('masks a cut Telegram token', () => {
    expect(maskCredentialsInLine('bot 1234567890:AAFq3xV9mK2pL8nR ...')).toBe('bot 1234567890:*** ...');
  });

  it('masks mysql -p<pw> in snippets', () => {
    const out = maskCredentialsInLine('exec("mysql -u root -paQfDPrAJ71fTquWoGsbeKXgzg2sye9b2 -e " + cmd)');
    expect(out).not.toContain('aQfDPrAJ');
    expect(out).toContain('-p***');
    expect(maskCredentialsInText('mysql -uroot -pHq7Zx3Rm9Lw2Np4Kv')).not.toContain('Hq7Zx3Rm');
  });

  it('masks a $-prefixed password that is not a variable name', () => {
    expect(maskCredentialsInLine('password: $uperS3cretHorse2024')).toBe('password: ***');
    expect(maskCredentialsInText('API_TOKEN=$xK9mQ2vL8pR4tW7yB1cD')).toBe('API_TOKEN=***');
    expect(maskCredentialsInText('API_TOKEN=$API_TOKEN')).toBe('API_TOKEN=$API_TOKEN');
    expect(maskCredentialsInText('API_TOKEN=${API_TOKEN}')).toBe('API_TOKEN=${API_TOKEN}');
  });
});

describe('report masking — dt21 g5-F5 / g5-F7: -k values and settings', () => {
  it('masks a -k value only when it is a random key', () => {
    const k = 'ZuluAlpha0987654321BravoCharlie12';
    expect(maskCredentialsDeep({ args: ['-y', 'acme-mcp', '-k', k] }).args).toEqual(['-y', 'acme-mcp', '-k', '***']);
    expect(maskCredentialsInText(`acme-mcp -k ${k}`)).toBe('acme-mcp -k ***');
    expect(maskCredentialsInText('curl -k https://x.example/api')).toBe('curl -k https://x.example/api');
    expect(maskCredentialsDeep({ args: ['curl', '-k', 'https://x.example'] }).args).toEqual(['curl', '-k', 'https://x.example']);
  });

  it('keeps settings about a credential readable in NAME = value snippets', () => {
    for (const line of ['ssh_session_ttl_secs = 0', 'max_tokens = 4096', 'session_timeout = 30', 'token_limit=100']) {
      expect(maskCredentialsInText(line), line).toBe(line);
    }
  });
});

describe('report masking — dt21 g2-F5 / g3 cosmetic: labels', () => {
  it('never reads a server label as a key', () => {
    expect(maskCredentialsInLine('Server "auth": @modelcontextprotocol/server-github@1.0.0')).toBe('Server "auth": @modelcontextprotocol/server-github@1.0.0');
    expect(maskCredentialsInLine('Server "secret-mgr": npx -y (auto-install)')).toBe('Server "secret-mgr": npx -y (auto-install)');
    expect(maskCredentialsInLine('Server "my-token-srv": args[2] --token ***')).toBe('Server "my-token-srv": args[2] --token ***');
    // the masked rest still masks
    expect(maskCredentialsInLine('Server "auth": args[1] --token q8Zr2Lm9Xc4Vb7Nt1Kp3')).toBe('Server "auth": args[1] --token ***');
  });

  it('keeps the sentence around a flag readable', () => {
    expect(maskCredentialsInText('Plaintext Telegram Bot token after --bot-token in server arguments'))
      .toBe('Plaintext Telegram Bot token after --bot-token in server arguments');
  });

  it('round-trips through toReportJson', () => {
    const out = toReportJson({ evidence: [{ snippet: 'Server "api-key-server": args[3] --apiToken 3Tz85pkNGcVx2RHLKXSf3wh34LxC' }] });
    expect(out).toContain('Server \\"api-key-server\\": args[3] --apiToken ***');
  });
});

describe('report masking — dt21: assignment labels in prose', () => {
  it('keeps "in password= in server arguments" readable', () => {
    expect(maskCredentialsInText('Plaintext credential in password= in server arguments')).toBe('Plaintext credential in password= in server arguments');
  });
});
