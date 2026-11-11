import { describe, expect, it } from 'vitest';
import { findSourceSecrets } from './source-secrets.js';

describe('findSourceSecrets — dt21 g3-F3: credentials inside command and URL strings', () => {
  const code = [
    `exec("curl -H 'Authorization: Bearer C3J27XDCG2LmlZGEONYlgCtjfIZ4SOcM' https://api.x.io/" + cmd);`,
    'exec(`PGPASSWORD=z9CPVNPkNa1Hedcm4pMbXDuCL1mHoOsF psql -h db -c ${cmd}`);',
    'exec("mysql -u root -paQfDPrAJ71fTquWoGsbeKXgzg2sye9b2 -e " + cmd);',
    'exec("redis-cli -u redis://:gadDZFlRJmCGmUXiAPyhzAnar3ZLt4bn@cache:6379 " + cmd);',
    'await fetch("https://u:lz2MPKgcjnCqaXNv1syeefnLOpaMxxND@collect.example.com/x", {method:"POST", body:d});',
    'exec("sshpass -p i9LE1Ki3ylOjt6o0NpUmkVO8JmR8y4EM ssh host " + cmd);',
  ].join('\n');

  it('finds each hardcoded credential, masked', () => {
    const found = findSourceSecrets(code);
    expect(found.map(f => f.line).sort()).toEqual([1, 2, 3, 4, 5, 6]);
    const text = JSON.stringify(found);
    for (const secret of ['C3J27XDCG2Lml', 'z9CPVNPkNa1H', 'aQfDPrAJ71fT', 'gadDZFlRJmCG', 'lz2MPKgcjnCq', 'i9LE1Ki3ylOj']) {
      expect(text).not.toContain(secret);
    }
  });

  it('stays quiet on references and placeholders', () => {
    for (const line of [
      'exec(`PGPASSWORD=${process.env.PGPASSWORD} psql`)',
      'fetch("https://user:${PASS}@host/x")',
      'exec("mysql -u root -p -e " + cmd)',
      'const url = "postgres://app:password@localhost/db"',
      'exec("curl -H \'Authorization: Bearer YOUR_TOKEN_HERE_PLACEHOLDER\'")',
    ]) {
      expect(findSourceSecrets(line), line).toEqual([]);
    }
  });
});
