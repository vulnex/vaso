import { describe, it, expect } from 'vitest';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import { cfg002 } from './cfg-002-api-key-exposure.js';
import { hookCommandSecrets } from '../../analyzers/hook-commands.js';

const PW = 'Tr0ub4dor-3xKcd9Zq7Wm2';

function settings(commands: string[]): ParsedConfig {
  const data = { hooks: { PreToolUse: [{ matcher: 'Bash', hooks: commands.map(command => ({ type: 'command', command })) }] } };
  return { raw: JSON.stringify(data, null, 1), format: 'json', filePath: '/home/test/.claude/settings.json', data };
}

function ctx(configs: ParsedConfig[]): ScanContext {
  const installation: AgentInstallation = { agent: 'claude-code', installDir: '/home/test/.claude', configFiles: configs };
  return { installation, configs, platform: 'linux', fs: { homedir: () => '/home/test' } as never };
}

describe('CFG-002 passwords in hook commands', () => {
  it('finds URL userinfo, Basic auth, --password and client -p passwords, masked', async () => {
    const basic = Buffer.from(`ci:${PW}`).toString('base64');
    const commands = [
      `curl -s https://ci:${PW}1@ci.example.com/hook`,
      `curl -s -H 'Authorization: Basic ${basic}' https://ci.example.com/`,
      `notify --password ${PW}2 --channel ops`,
      `mysql -uroot -p${PW}3 -e 'select 1'`,
      `sshpass -p '${PW}4' ssh deploy@host true`,
    ];
    const r = await cfg002.run(ctx([settings(commands)]));
    expect(r.passed).toBe(false);
    expect(r.evidence).toHaveLength(commands.length);
    for (const e of r.evidence ?? []) {
      expect(e.detail).toMatch(/in a hook command$/);
      expect(e.snippet).not.toContain(PW);
      expect(e.snippet).not.toContain(basic);
      expect(e.line).toBeGreaterThan(0);
    }
  });

  it('leaves variables, placeholders and a -p that is not a password alone', async () => {
    const r = await cfg002.run(ctx([settings([
      'curl -s https://ci:$CI_PASSWORD@ci.example.com/hook',
      'notify --password "${NOTIFY_PASSWORD}"',
      'notify --password <your-password>',
      'psql -h db -p 5432 -U app',
      'docker run -p 8080:80 img',
      'git commit -m "update password docs"',
      // MySQL takes the password glued: a separate -p value is the database
      'mysql -u root -p app_db',
      'mysql -h db -P 3306 -u app -p mydb',
    ])]));
    expect(r.passed).toBe(true);
  });

  it('names every hook a repeated password appears in', async () => {
    const data = { hooks: {
      PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: `sshpass -p ${PW} ssh a true` }] }],
      Stop: [{ hooks: [{ type: 'command', command: `sshpass -p ${PW} ssh b true` }] }],
    } };
    const r = await cfg002.run(ctx([{ raw: JSON.stringify(data, null, 1), format: 'json', filePath: '/home/test/.claude/settings.json', data }]));
    expect(r.evidence).toHaveLength(1);
    expect(r.evidence?.[0].detail).toMatch(/PreToolUse \(Bash\), Stop — same value/);
    expect(JSON.stringify(r.evidence)).not.toContain(PW);
  });

  it('does not report a token twice when a known format already matched the line', async () => {
    const r = await cfg002.run(ctx([settings(['curl -H "Authorization: Bearer ghp_R4nD0mT0k3nV4lu3XyZq9W8e7R6t5Y4u3I2o" https://api.github.com'])]));
    expect(r.evidence).toHaveLength(1);
    expect(r.evidence?.[0].detail).toBe('Found GitHub PAT');
  });

  it('reads a quoted command inside a hook command as argv too', async () => {
    const r = await cfg002.run(ctx([settings([
      `ssh db1 "mysql -u root -p${PW}5 app"`,
      `bash -c 'sshpass -p ${PW}6 ssh deploy@host true'`,
    ])]));
    expect(r.evidence).toHaveLength(2);
    expect(JSON.stringify(r.evidence)).not.toContain(PW);
    // the nested database-not-password rule still holds
    const db = await cfg002.run(ctx([settings(['ssh db1 "mysql -u root -p app_db"', 'git commit -m "mysql -p mydb docs"'])]));
    expect(db.passed).toBe(true);
  });

  it('hookCommandSecrets reads each statement as argv', () => {
    const found = hookCommandSecrets(`echo start; curl https://u:${PW}@h.example/x && notify --password=${PW}x`);
    expect(found.map(s => s.value)).toEqual([PW, `${PW}x`]);
    expect(found.every(s => !s.masked.includes(PW))).toBe(true);
  });
});
