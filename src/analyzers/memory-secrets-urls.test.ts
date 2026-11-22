import { describe, it, expect } from 'vitest';
import { scanMemorySecrets } from './memory-secrets.js';

describe('scanMemorySecrets: credentials inside URLs (dt24)', () => {
  it('flags connection-string passwords without quoting them', () => {
    const pw = 'Xq7mR2vL9pTz';
    const text = [
      `Dev database: postgres://app:${pw}@db.internal:5432/app`,
      `Atlas: mongodb+srv://svc:${pw}Q@cluster0.example.net/test.`,
    ].join('\n');
    const ev = scanMemorySecrets('/home/alice/.claude/CLAUDE.md', text);
    expect(ev.map(e => e.line)).toEqual([1, 2]);
    expect(ev[0].detail).toMatch(/password in URL userinfo/);
    expect(JSON.stringify(ev)).not.toContain(pw.slice(0, 4));
  });

  it('passes placeholders, references and plain URLs', () => {
    const text = [
      'Use postgres://user:password@localhost:5432/db for local work',
      'Set DATABASE_URL=postgres://app:${DB_PASSWORD}@db/app',
      'Docs: https://example.com/guide?page=2',
      'mongodb+srv://<user>:<password>@cluster0.example.net',
    ].join('\n');
    expect(scanMemorySecrets('/home/alice/.claude/CLAUDE.md', text)).toEqual([]);
  });
});
