import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, AgentInstallation } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { run001 } from './run-001-launch-agents.js';
import { run002 } from './run-002-suspicious-cron.js';
import { run003 } from './run-003-vscode-trojans.js';
import { run004 } from './run-004-docker-security.js';
import { launchdCommand, systemdCommand } from './run-001-launch-agents.js';
import { run005 } from './run-005-process-ancestry.js';

function makeContext(): ScanContext {
  const installation: AgentInstallation = {
    agent: 'openclaw',
    installDir: '/tmp/test-openclaw',
    configFiles: [],
  };
  return { installation, configs: [], platform: process.platform as NodeJS.Platform, fs: new LocalFSProvider() };
}

function makeMockedFs(filesByDir: Record<string, string[]>, platform: NodeJS.Platform = 'darwin'): FSProvider {
  return {
    readdir: vi.fn(async (dir: string) => filesByDir[dir] ?? []),
    readFile: vi.fn(async () => ''),
    readBytes: vi.fn(async () => new Uint8Array()),
    readdirEntries: vi.fn(async () => []),
    access: vi.fn(async () => true),
    stat: vi.fn(),
    realpath: vi.fn(),
    exec: vi.fn(),
    execSync: vi.fn(),
    getEnv: vi.fn(),
    homedir: () => '/home/test',
    platform,
  } as FSProvider;
}

function makeRunCtx(fs: FSProvider, platform: NodeJS.Platform = 'darwin'): ScanContext {
  const installation: AgentInstallation = {
    agent: 'openclaw',
    installDir: '/home/test/.openclaw',
    configFiles: [],
  };
  return { installation, configs: [], platform, fs };
}

describe('RUN-001: Unauthorized LaunchAgents', () => {
  it('does not flag generic Apple/Google/Microsoft LaunchAgents with "agent" in the name', async () => {
    const fs = makeMockedFs({
      '/home/test/Library/LaunchAgents': [
        'com.google.keystone.agent.plist',
        'com.microsoft.update.agent.plist',
        'com.apple.SafariBookmarksSyncAgent.plist',
      ],
      '/Library/LaunchAgents': [],
      '/Library/LaunchDaemons': [],
    });
    const result = await run001.run(makeRunCtx(fs));
    expect(result.passed).toBe(true);
  });

  it('flags LaunchAgents that reference *claw frameworks', async () => {
    const fs = makeMockedFs({
      '/home/test/Library/LaunchAgents': ['com.openclaw.gateway.plist'],
      '/Library/LaunchAgents': [],
      '/Library/LaunchDaemons': [],
    });
    const result = await run001.run(makeRunCtx(fs));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].file).toContain('openclaw');
  });

  it('flags LaunchAgents that reference nanobot', async () => {
    const fs = makeMockedFs({
      '/home/test/Library/LaunchAgents': ['com.nanobot.persistence.plist'],
      '/Library/LaunchAgents': [],
      '/Library/LaunchDaemons': [],
    });
    const result = await run001.run(makeRunCtx(fs));
    expect(result.passed).toBe(false);
  });

  it('leaves another framework\'s own service to that framework (Linux)', async () => {
    const fs = makeMockedFs({ '/home/test/.config/systemd/user': ['nanobot-gateway.service'] }, 'linux');
    (fs.readFile as ReturnType<typeof vi.fn>).mockResolvedValue(
      '[Service]\nExecStart=/home/test/.local/bin/nanobot gateway\n');
    const result = await run001.run(makeRunCtx(fs, 'linux'));
    expect(result.passed).toBe(true);
  });

  it('recognizes an interpreter running the install\'s own script (bun run / npx tsx)', async () => {
    for (const exec of [
      '/home/test/.bun/bin/bun run /home/test/agent-checkout/scripts/daemon.ts',
      '/usr/bin/npx tsx /home/test/agent-checkout/scripts/daemon.ts',
      '/usr/bin/node --enable-source-maps /home/test/agent-checkout/dist/daemon.js',
    ]) {
      const fs = makeMockedFs({ '/home/test/.config/systemd/user': ['lyrie-agent.service'] }, 'linux');
      (fs.readFile as ReturnType<typeof vi.fn>).mockResolvedValue(`[Service]\nExecStart=${exec}\n`);
      const ctx = makeRunCtx(fs, 'linux');
      ctx.installation = { agent: 'lyrie', installDir: '/home/test/agent-checkout', configFiles: [] };
      const result = await run001.run(ctx);
      expect(result.evidence?.[0].mitigated, exec).toBe(true);
    }
  });

  it('still reports a suspicious unit named after another framework', async () => {
    const fs = makeMockedFs({ '/home/test/.config/systemd/user': ['nanobot-gateway.service'] }, 'linux');
    (fs.readFile as ReturnType<typeof vi.fn>).mockResolvedValue(
      '[Service]\nExecStart=/tmp/nanobot gateway\n');
    const result = await run001.run(makeRunCtx(fs, 'linux'));
    expect(result.passed).toBe(false);
  });

  it('does not match the generic word "skill"', async () => {
    const fs = makeMockedFs({
      '/home/test/Library/LaunchAgents': ['com.amazon.alexa.skill-builder.plist'],
      '/Library/LaunchAgents': [],
      '/Library/LaunchDaemons': [],
    });
    const result = await run001.run(makeRunCtx(fs));
    expect(result.passed).toBe(true);
  });

  it('passes when no LaunchAgents directories are readable', async () => {
    const fs: FSProvider = {
      readdir: vi.fn(async () => { throw new Error('ENOENT'); }),
      readFile: vi.fn(async () => ''),
      readBytes: vi.fn(async () => new Uint8Array()),
      readdirEntries: vi.fn(async () => []),
      access: vi.fn(async () => false),
      stat: vi.fn(),
      realpath: vi.fn(),
      exec: vi.fn(),
      execSync: vi.fn(),
      getEnv: vi.fn(),
      homedir: () => '/home/test',
      platform: 'darwin',
    } as FSProvider;
    const result = await run001.run(makeRunCtx(fs));
    expect(result.passed).toBe(true);
  });
});

function makeCronCtx(crontabOutput: string | Error): ScanContext {
  const fs: FSProvider = {
    readdir: vi.fn(async () => []),
    readFile: vi.fn(async () => ''),
    readBytes: vi.fn(async () => new Uint8Array()),
    readdirEntries: vi.fn(async () => []),
    access: vi.fn(async () => false),
    stat: vi.fn(),
    realpath: vi.fn(),
    exec: vi.fn(),
    execSync: vi.fn(() => {
      if (crontabOutput instanceof Error) throw crontabOutput;
      return crontabOutput;
    }),
    getEnv: vi.fn(),
    homedir: () => '/home/test',
    platform: 'linux',
  } as FSProvider;

  const installation: AgentInstallation = {
    agent: 'openclaw',
    installDir: '/home/test/.openclaw',
    configFiles: [],
  };
  return { installation, configs: [], platform: 'linux', fs };
}

describe('RUN-002: Suspicious Cron Entries', () => {
  it('does not flag generic cron entries that just contain "agent" or "skill"', async () => {
    const crontab = [
      '0 * * * * /usr/local/bin/google-keystone-agent --check-for-updates',
      '*/5 * * * * /opt/alexa-skill-builder/sync.sh',
      '@reboot /usr/bin/systemd-user-agent --start',
    ].join('\n');
    const result = await run002.run(makeCronCtx(crontab));
    expect(result.passed).toBe(true);
  });

  it('flags cron entries that reference *claw frameworks', async () => {
    const crontab = '0 * * * * /home/me/.openclaw/scripts/persistence.sh';
    const result = await run002.run(makeCronCtx(crontab));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].snippet).toContain('openclaw');
  });

  it('flags cron entries that reference nanobot', async () => {
    const crontab = '*/10 * * * * /usr/local/bin/nanobot heartbeat';
    const result = await run002.run(makeCronCtx(crontab));
    expect(result.passed).toBe(false);
  });

  it('passes when crontab is unavailable', async () => {
    const result = await run002.run(makeCronCtx(new Error('no crontab')));
    expect(result.passed).toBe(true);
  });

  it('skips comment lines', async () => {
    const crontab = '# this is a comment about openclaw\n# nothing real here';
    const result = await run002.run(makeCronCtx(crontab));
    expect(result.passed).toBe(true);
  });
});

describe('RUN-005: Process Ancestry Analysis', () => {
  it('returns a valid CheckResult', async () => {
    const result = await run005.run(makeContext());
    expect(result.id).toBe('RUN-005');
    expect(result.category).toBe('runtime');
    expect(result.severity).toBe('warning');
    expect(typeof result.passed).toBe('boolean');
    expect(typeof result.message).toBe('string');
  });

  it('is limited to darwin and linux platforms', () => {
    expect(run005.supportedPlatforms).toEqual(['darwin', 'linux']);
  });

  it('walks every agent process — a first hit no longer hides the next one', async () => {
    const ps = [
      '  PID  PPID COMM',
      '  100     1 python3',
      '  200   100 openclaw',
      '  300     1 curl',
      '  400   300 openclaw-gateway',
    ].join('\n');
    const fs = makeMockedFs({});
    (fs.execSync as ReturnType<typeof vi.fn>).mockReturnValue(ps);
    const r = await run005.run({ installation: { agent: 'openclaw', installDir: '/h', configFiles: [] }, configs: [], platform: 'linux', fs });
    expect(r.evidence?.map(e => e.detail)).toEqual([
      'Agent process "openclaw" (PID 200) has suspicious parent "python3" (PID 100)',
      'Agent process "openclaw-gateway" (PID 400) has suspicious parent "curl" (PID 300)',
    ]);
  });

  it("reports only the scanned installation's own processes", async () => {
    const ps = [
      '  PID  PPID COMM',
      '  100     1 python3',
      '  200   100 openclaw',
      '  300     1 bash',
      '  400   300 hermes',
    ].join('\n');
    const fs = makeMockedFs({});
    (fs.execSync as ReturnType<typeof vi.fn>).mockReturnValue(ps);
    const ctxFor = (agent: AgentInstallation['agent']): ScanContext => ({
      installation: { agent, installDir: '/h', configFiles: [] }, configs: [], platform: 'linux', fs,
    });
    const openclaw = await run005.run(ctxFor('openclaw'));
    expect(openclaw.passed).toBe(false);
    expect(openclaw.evidence?.[0].detail).toContain('"openclaw" (PID 200) has suspicious parent "python3"');
    // The same process is not attributed to other frameworks on the host
    expect((await run005.run(ctxFor('atomic-agent'))).passed).toBe(true);
    // Hermes processes are examined for Hermes (bash parent is not suspicious by name)
    expect((await run005.run(ctxFor('hermes'))).passed).toBe(true);
  });

  it('passes when no agent processes are running', async () => {
    // In a test environment, no openclaw/nanoclaw/etc processes should be running
    const result = await run005.run(makeContext());
    expect(result.passed).toBe(true);
  });
});

describe('RUN-003: VS Code Extension Trojans', () => {
  it('flags a known malicious VS Code extension directory', async () => {
    const fs = makeMockedFs({
      '/home/test/.vscode/extensions': ['clawdbot.clawdbot-agent-0.0.1'],
      '/home/test/.vscode-insiders/extensions': [],
      '/home/test/.cursor/extensions': ['anthropic.claude-code-2.1.313-darwin-arm64', 'anthropic.claude-code-2.1.314-darwin-arm64'],
    });
    const result = await run003.run(makeRunCtx(fs));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
    expect(result.evidence!.map(e => e.file)).toEqual([
      '/home/test/.vscode/extensions/clawdbot.clawdbot-agent-0.0.1',
      '/home/test/.cursor/extensions/anthropic.claude-code-2.1.313-darwin-arm64',
    ]);
  });

  it('matches the whole extension id, not a prefix and a substring', async () => {
    const fs = makeMockedFs({
      '/home/test/.vscode/extensions': ['clawdbot.clawdbot-agent-helper-1.0.0', 'clawdbotx.clawdbot-agent-1.0.0'],
      '/home/test/.vscode-insiders/extensions': [],
      '/home/test/.cursor/extensions': [],
    });
    expect((await run003.run(makeRunCtx(fs))).passed).toBe(true);
  });

  it('passes when no extension directory contains a known malicious ID', async () => {
    const fs = makeMockedFs({
      '/home/test/.vscode/extensions': [
        'ms-python.python-2026.0.0',
        'esbenp.prettier-vscode-9.0.0',
      ],
      '/home/test/.vscode-insiders/extensions': [],
      '/home/test/.cursor/extensions': [],
    });
    const result = await run003.run(makeRunCtx(fs));
    expect(result.passed).toBe(true);
  });
});

describe('RUN-004: Docker Security', () => {
  it('passes when /var/run/docker.sock is not accessible (or absent)', async () => {
    const fs: FSProvider = {
      readdir: vi.fn(async () => []),
      readFile: vi.fn(async () => ''),
      readBytes: vi.fn(async () => new Uint8Array()),
      readdirEntries: vi.fn(async () => []),
      access: vi.fn(async () => false),
      stat: vi.fn(async () => { throw new Error('ENOENT'); }),
      realpath: vi.fn(),
      exec: vi.fn(),
      execSync: vi.fn(),
      getEnv: vi.fn(),
      homedir: () => '/home/test',
      platform: 'linux',
    } as FSProvider;
    const result = await run004.run(makeRunCtx(fs, 'linux'));
    expect(result.passed).toBe(true);
  });

  it('flags a world-accessible docker socket', async () => {
    const fs: FSProvider = {
      readdir: vi.fn(async () => []),
      readFile: vi.fn(async () => ''),
      readBytes: vi.fn(async () => new Uint8Array()),
      readdirEntries: vi.fn(async () => []),
      access: vi.fn(async () => true),
      stat: vi.fn(async () => ({
        mode: 0o666,
        isFile: () => false,
        isDirectory: () => false,
      })),
      realpath: vi.fn(),
      exec: vi.fn(),
      execSync: vi.fn(),
      getEnv: vi.fn(),
      homedir: () => '/home/test',
      platform: 'linux',
    } as FSProvider;
    const result = await run004.run(makeRunCtx(fs, 'linux'));
    expect(result.passed).toBe(false);
    expect(result.evidence![0].file).toBe('/var/run/docker.sock');
  });

  // Connecting to a Unix socket requires write permission
  for (const [mode, why] of [[0o755, 'Docker Desktop on macOS'], [0o660, 'root:docker group on Linux']] as const) {
    it(`passes a ${mode.toString(8)} socket (${why}) — not connectable by other users`, async () => {
      const fs = {
        access: vi.fn(async () => true),
        stat: vi.fn(async () => ({ mode, isFile: () => false, isDirectory: () => false })),
        platform: 'linux',
      } as unknown as FSProvider;
      const result = await run004.run(makeRunCtx(fs, 'linux'));
      expect(result.passed).toBe(true);
    });
  }
});

// Real units from the Linux test box: OpenClaw's own gateway service must not
// read as malware persistence; a keyword-named binary elsewhere still does.
describe('RUN-001: agent services vs. suspicious persistence', () => {
  const UNIT_DIR = '/home/test/.config/systemd/user';
  function linuxFs(units: Record<string, string>): FSProvider {
    return {
      readdir: vi.fn(async (dir: string) => (dir === UNIT_DIR ? Object.keys(units) : [])),
      readFile: vi.fn(async (p: string) => units[p.slice(UNIT_DIR.length + 1)] ?? ''),
      homedir: () => '/home/test',
      platform: 'linux',
    } as unknown as FSProvider;
  }

  it('reports the installed OpenClaw gateway (CLI wrapper and node forms) as info', async () => {
    const fs = linuxFs({
      'openclaw-gateway.service': '[Service]\nExecStart=/home/test/.local/bin/openclaw gateway --port 18789\n',
      'openclaw-gateway.service.bak':
        '[Service]\nExecStart=/usr/bin/node /home/test/.nvm/versions/node/v22.22.1/lib/node_modules/openclaw/dist/index.js gateway\n',
    });
    const result = await run001.run(makeRunCtx(fs, 'linux'));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('info');
    expect(result.message).toContain('all run an installed agent');
    expect(result.evidence?.every(e => e.mitigated)).toBe(true);
  });

  it('keeps warning severity for a keyword-named binary outside install roots', async () => {
    const fs = linuxFs({
      'openclaw-gateway.service': '[Service]\nExecStart=/home/test/.local/bin/openclaw gateway\n',
      'clawbot-update.service': '[Service]\nExecStart=/tmp/.x/clawbot --daemon\n',
    });
    const result = await run001.run(makeRunCtx(fs, 'linux'));
    expect(result.severity).toBe('warning');
    expect(result.message).toBe('Found 1 suspicious persistence mechanism(s)');
    const bad = result.evidence!.find(e => !e.mitigated)!;
    expect(bad.detail).toContain('/tmp/.x/clawbot');
  });

  it('parses ExecStart prefixes/quotes and launchd Program/ProgramArguments', () => {
    expect(systemdCommand('ExecStart=-"/opt/My App/bin/nanobot" run')).toEqual(['/opt/My App/bin/nanobot', 'run']);
    const plist = '<dict><key>ProgramArguments</key><array><string>/opt/homebrew/bin/openclaw</string><string>gateway</string></array></dict>';
    expect(launchdCommand(plist)).toEqual(['/opt/homebrew/bin/openclaw', 'gateway']);
  });
});

