import { describe, expect, it } from 'vitest';
import { maskCredentialsDeep, maskCredentialsInLine, maskCredentialsInText } from './serialize.js';
import { findArgSecrets } from '../mcp/config-secrets.js';

describe('--pw / --pass and curl user:password', () => {
  it('masks a plain value after --pw or --pass, in argv and in text', () => {
    const { args } = maskCredentialsDeep({ command: 'acme', args: ['--pw', 'pwflaglow', '--pass', 'passflaglow', '--db-pw=dbpwlow'] });
    const joined = args.join(' ');
    for (const s of ['pwflaglow', 'passflaglow', 'dbpwlow']) expect(joined).not.toContain(s);
    expect(joined).toContain('--pw');
    for (const out of [maskCredentialsInText('acme --pw pwflaglow'), maskCredentialsInLine('acme --pw pwflaglow')]) {
      expect(out).not.toContain('pwflaglow');
      expect(out).toContain('--pw');
    }
  });

  it('masks curl -u/--user passwords given as separate elements, keeping the user', () => {
    const { args } = maskCredentialsDeep({ command: 'curl', args: ['-u', 'carol:curlpw2low', '--user', 'dave:userpwlow', 'https://x.example'] });
    expect(args).toEqual(['-u', 'carol:***', '--user', 'dave:***', 'https://x.example']);
  });

  it('reports curl passwords (MCP-003) but not another command\'s -u user:group', () => {
    expect(findArgSecrets(['-u', 'carol:curlpw2low'], 'curl').map(s => s.masked)).toEqual(['-u carol:***']);
    expect(findArgSecrets(['run', '-u', 'app:appgroup', 'img'], 'docker')).toEqual([]);
    expect(findArgSecrets(['curl', '--user=erin:hunter2abc'], 'sh').map(s => s.value)).toEqual(['hunter2abc']);
  });
});
