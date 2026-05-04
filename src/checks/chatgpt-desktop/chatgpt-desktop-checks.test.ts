import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { chatgptDesktopChecks } from './index.js';

function makeConfig(filePath: string, data: Record<string, unknown>): ParsedConfig {
  return {
    raw: JSON.stringify(data, null, 2),
    format: 'json',
    filePath,
    data,
  };
}

function makeFs(overrides: Partial<FSProvider> = {}): FSProvider {
  return {
    access: vi.fn(async () => true),
    stat: vi.fn(async () => ({ mode: 0o600, isFile: () => true, isDirectory: () => false })),
    readFile: vi.fn(),
    readdir: vi.fn(),
    readdirEntries: vi.fn(async () => []),
    realpath: vi.fn(),
    exec: vi.fn(),
    execSync: vi.fn(),
    getEnv: vi.fn(() => undefined),
    homedir: () => '/Users/test',
    platform: 'darwin',
    ...overrides,
  } as FSProvider;
}

function makeCtx(configs: ParsedConfig[], fs?: FSProvider, appBundle?: string): ScanContext {
  const installation: AgentInstallation = {
    agent: 'chatgpt-desktop',
    installDir: '/Users/test/Library/Application Support/com.openai.chat',
    configFiles: configs,
    appBundle,
  };
  return { installation, configs, platform: 'darwin', fs: fs ?? makeFs() };
}

describe('ChatGPT Desktop checks', () => {
  it('exports 6 checks', () => {
    expect(chatgptDesktopChecks).toHaveLength(6);
  });

  it('all checks have coding-agent category and supportedAgents', () => {
    for (const check of chatgptDesktopChecks) {
      expect(check.category).toBe('coding-agent');
      expect(check.supportedAgents).toContain('chatgpt-desktop');
      expect(check.supportedPlatforms).toContain('darwin');
    }
  });

  it('all check IDs start with CG-', () => {
    for (const check of chatgptDesktopChecks) {
      expect(check.id).toMatch(/^CG-0\d{2}$/);
    }
  });
});

describe('CG-001: Workspace Data Files World-Readable', () => {
  const check = chatgptDesktopChecks.find(c => c.id === 'CG-001')!;

  it('fails when conversation .data files are mode 644', async () => {
    const fs = makeFs({
      readdirEntries: vi.fn(async (path: string) => {
        if (path.endsWith('com.openai.chat')) {
          return [{ name: 'conversations-v3-abc', isDirectory: true, isFile: false }];
        }
        return [{ name: 'conv1.data', isFile: true, isDirectory: false }];
      }) as FSProvider['readdirEntries'],
      stat: vi.fn(async () => ({ mode: 0o644, isFile: () => true, isDirectory: () => false })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(false);
  });

  it('passes when conversation .data files are mode 600', async () => {
    const fs = makeFs({
      readdirEntries: vi.fn(async (path: string) => {
        if (path.endsWith('com.openai.chat')) {
          return [{ name: 'conversations-v3-abc', isDirectory: true, isFile: false }];
        }
        return [{ name: 'conv1.data', isFile: true, isDirectory: false }];
      }) as FSProvider['readdirEntries'],
      stat: vi.fn(async () => ({ mode: 0o600, isFile: () => true, isDirectory: () => false })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });

  it('skips unrelated subdirectories', async () => {
    const fs = makeFs({
      readdirEntries: vi.fn(async (path: string) => {
        if (path.endsWith('com.openai.chat')) {
          return [{ name: 'io.sentry', isDirectory: true, isFile: false }];
        }
        return [{ name: 'crash.json', isFile: true, isDirectory: false }];
      }) as FSProvider['readdirEntries'],
      stat: vi.fn(async () => ({ mode: 0o644, isFile: () => true, isDirectory: () => false })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });
});

describe('CG-002: Account Email Stored in Plaintext', () => {
  const check = chatgptDesktopChecks.find(c => c.id === 'CG-002')!;

  it('fails when StatsigService.plist holds a userEmail', async () => {
    const config = makeConfig('/path/com.openai.chat.StatsigService.plist', {
      userEmail: 'user@example.com',
      userID: 'user-abc',
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].snippet).toContain('@');
    // Confirm we mask the email rather than echoing it verbatim
    expect(result.evidence?.[0].snippet).not.toContain('user@example.com');
  });

  it('passes when no email field is present', async () => {
    const config = makeConfig('/path/com.openai.chat.StatsigService.plist', {
      userID: 'user-abc',
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });

  it('ignores other plists', async () => {
    const config = makeConfig('/path/com.openai.chat.plist', {
      userEmail: 'user@example.com',
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('CG-003: Training Data Opt-In Active', () => {
  const check = chatgptDesktopChecks.find(c => c.id === 'CG-003')!;

  it('fails when trainingAllowed is true', async () => {
    const config = makeConfig('/path/com.openai.chat.plist', {
      lastAccountSettingsResponse_abc: JSON.stringify({
        settings: { trainingAllowed: true },
      }),
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when trainingAllowed is false', async () => {
    const config = makeConfig('/path/com.openai.chat.plist', {
      lastAccountSettingsResponse_abc: JSON.stringify({
        settings: { trainingAllowed: false },
      }),
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });

  it('passes when account-settings JSON is unparseable', async () => {
    const config = makeConfig('/path/com.openai.chat.plist', {
      lastAccountSettingsResponse_abc: 'not-json',
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('CG-004: Precise Location Enabled', () => {
  const check = chatgptDesktopChecks.find(c => c.id === 'CG-004')!;

  it('fails when preciseLocationAllowed is true', async () => {
    const config = makeConfig('/path/com.openai.chat.plist', {
      lastAccountSettingsResponse_abc: JSON.stringify({
        settings: { preciseLocationAllowed: true },
      }),
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when preciseLocationAllowed is false', async () => {
    const config = makeConfig('/path/com.openai.chat.plist', {
      lastAccountSettingsResponse_abc: JSON.stringify({
        settings: { preciseLocationAllowed: false },
      }),
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('CG-005: ChatGPT.app Codesign / Team ID', () => {
  const check = chatgptDesktopChecks.find(c => c.id === 'CG-005')!;

  it('passes when codesign reports the expected Team ID and identifier', async () => {
    const fs = makeFs({
      exec: vi.fn(async () => ({
        stdout: '',
        stderr:
          'Executable=/Applications/ChatGPT.app/Contents/MacOS/ChatGPT\nIdentifier=com.openai.chat\nTeamIdentifier=2DC432GLL2\n',
        exitCode: 0,
      })),
    });
    const result = await check.run(makeCtx([], fs, '/Applications/ChatGPT.app'));
    expect(result.passed).toBe(true);
  });

  it('fails on Team ID mismatch', async () => {
    const fs = makeFs({
      exec: vi.fn(async () => ({
        stdout: '',
        stderr:
          'Executable=/Applications/ChatGPT.app/Contents/MacOS/ChatGPT\nIdentifier=com.openai.chat\nTeamIdentifier=DEADBEEF12\n',
        exitCode: 0,
      })),
    });
    const result = await check.run(makeCtx([], fs, '/Applications/ChatGPT.app'));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('fails when codesign returns no identifiers (unsigned bundle)', async () => {
    const fs = makeFs({
      exec: vi.fn(async () => ({ stdout: '', stderr: 'no signature', exitCode: 1 })),
    });
    const result = await check.run(makeCtx([], fs, '/Applications/ChatGPT.app'));
    expect(result.passed).toBe(false);
  });

  it('passes (no-op) when ChatGPT.app is not installed', async () => {
    const result = await check.run(makeCtx([], makeFs(), undefined));
    expect(result.passed).toBe(true);
  });
});

describe('CG-006: Paired Apps Inventory', () => {
  const check = chatgptDesktopChecks.find(c => c.id === 'CG-006')!;

  it('passes when no app_pairing_extensions directory exists', async () => {
    const fs = makeFs({ access: vi.fn(async () => false) });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });

  it('passes with informational evidence when connectors are present', async () => {
    const fs = makeFs({
      access: vi.fn(async () => true),
      readdirEntries: vi.fn(async () => [
        { name: 'gmail.json', isFile: true, isDirectory: false },
        { name: 'google-drive.json', isFile: true, isDirectory: false },
      ]),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
    expect(result.evidence).toHaveLength(2);
    expect(result.message).toContain('2');
  });
});
