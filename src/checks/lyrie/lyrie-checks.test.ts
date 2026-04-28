import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider, DirentInfo } from '../../core/fs-provider.js';
import { lyrieChecks } from './index.js';

function makeEnv(filePath: string, data: Record<string, unknown>, raw?: string): ParsedConfig {
  return {
    raw: raw ?? Object.entries(data).map(([k, v]) => `${k}=${v}`).join('\n'),
    format: 'env',
    filePath,
    data,
  };
}

interface FsOverrides {
  files?: Record<string, string>;
  modes?: Record<string, number>;
  dirs?: Record<string, string[]>;
  dirEntries?: Record<string, DirentInfo[]>;
  whichResults?: Record<string, string>;
  versionResults?: Record<string, string>;
}

function makeFs(o: FsOverrides = {}): FSProvider {
  const exists = (p: string) =>
    p in (o.files ?? {}) || p in (o.modes ?? {}) || p in (o.dirs ?? {}) || p in (o.dirEntries ?? {});

  return {
    access: vi.fn(async (p: string) => exists(p)),
    stat: vi.fn(async (p: string) => ({
      mode: o.modes?.[p] ?? 0o600,
      isFile: () => true,
      isDirectory: () => p in (o.dirs ?? {}) || p in (o.dirEntries ?? {}),
    })),
    readFile: vi.fn(async (p: string) => {
      const v = o.files?.[p];
      if (v == null) throw new Error(`ENOENT ${p}`);
      return v;
    }),
    readdir: vi.fn(async (p: string) => o.dirs?.[p] ?? []),
    readdirEntries: vi.fn(async (p: string) => o.dirEntries?.[p] ?? []),
    realpath: vi.fn(async (p: string) => p),
    exec: vi.fn(),
    execSync: vi.fn((cmd: string, args: string[]) => {
      if (cmd === 'which' && args[0] && o.whichResults?.[args[0]]) return o.whichResults[args[0]] + '\n';
      if (o.versionResults?.[cmd]) return o.versionResults[cmd];
      throw new Error('not found');
    }),
    homedir: () => '/home/test',
    getEnv: vi.fn(() => undefined),
    platform: 'linux',
  } as FSProvider;
}

function makeCtx(configs: ParsedConfig[], opts: { installDir?: string; fs?: FSProvider } = {}): ScanContext {
  const installDir = opts.installDir ?? '/home/test/.lyrie';
  const installation: AgentInstallation = {
    agent: 'lyrie',
    installDir,
    skillsDir: `${installDir}/skills`,
    configFiles: configs,
  };
  return {
    installation,
    configs,
    platform: 'linux',
    fs: opts.fs ?? makeFs(),
  };
}

describe('Lyrie checks', () => {
  it('exports 18 checks', () => {
    expect(lyrieChecks).toHaveLength(18);
  });

  it('all checks have lyrie category and supportedAgents', () => {
    for (const check of lyrieChecks) {
      expect(check.category).toBe('lyrie');
      expect(check.supportedAgents).toContain('lyrie');
    }
  });

  it('all check IDs match LY-NNN', () => {
    for (const check of lyrieChecks) {
      expect(check.id).toMatch(/^LY-0\d{2}$/);
    }
  });
});

describe('LY-001: Shield Mode Passive', () => {
  const check = lyrieChecks.find(c => c.id === 'LY-001')!;

  it('fails when LYRIE_SHIELD_MODE=passive', async () => {
    const result = await check.run(makeCtx([makeEnv('.env', { LYRIE_SHIELD_MODE: 'passive' })]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('passes when LYRIE_SHIELD_MODE=active', async () => {
    const result = await check.run(makeCtx([makeEnv('.env', { LYRIE_SHIELD_MODE: 'active' })]));
    expect(result.passed).toBe(true);
  });
});

describe('LY-002: Shield Binary Missing', () => {
  const check = lyrieChecks.find(c => c.id === 'LY-002')!;

  it('fails when lyrie-shield not on PATH', async () => {
    const result = await check.run(makeCtx([], { fs: makeFs({}) }));
    expect(result.passed).toBe(false);
  });

  it('passes when lyrie-shield is found and runnable', async () => {
    const fs = makeFs({
      whichResults: { 'lyrie-shield': '/usr/local/bin/lyrie-shield' },
      versionResults: { '/usr/local/bin/lyrie-shield': 'lyrie-shield 0.1.0' },
    });
    const result = await check.run(makeCtx([], { fs }));
    expect(result.passed).toBe(true);
  });
});

describe('LY-003: DM Policy Open on Live Channel', () => {
  const check = lyrieChecks.find(c => c.id === 'LY-003')!;

  it('fails for telegram with token but no policy', async () => {
    const result = await check.run(makeCtx([makeEnv('.env', {
      TELEGRAM_BOT_TOKEN: '1234567890:ABC',
    })]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('fails for any channel with policy=open', async () => {
    const result = await check.run(makeCtx([makeEnv('.env', {
      LYRIE_MATRIX_TOKEN: 'tok',
      LYRIE_MATRIX_DM_POLICY: 'open',
    })]));
    expect(result.passed).toBe(false);
  });

  it('passes when channel has pairing policy', async () => {
    const result = await check.run(makeCtx([makeEnv('.env', {
      DISCORD_BOT_TOKEN: 'tok',
      LYRIE_DISCORD_DM_POLICY: 'pairing',
    })]));
    expect(result.passed).toBe(true);
  });

  it('passes when no channels are configured', async () => {
    const result = await check.run(makeCtx([makeEnv('.env', { LYRIE_SHIELD_MODE: 'active' })]));
    expect(result.passed).toBe(true);
  });
});

describe('LY-004: Pairing Store Permissions', () => {
  const check = lyrieChecks.find(c => c.id === 'LY-004')!;

  it('fails when pairing.json is mode 0644', async () => {
    const fs = makeFs({ modes: { '/home/test/.lyrie/pairing.json': 0o644 } });
    const result = await check.run(makeCtx([], { fs }));
    expect(result.passed).toBe(false);
  });

  it('passes when pairing.json is mode 0600', async () => {
    const fs = makeFs({ modes: { '/home/test/.lyrie/pairing.json': 0o600 } });
    const result = await check.run(makeCtx([], { fs }));
    expect(result.passed).toBe(true);
  });

  it('passes when pairing.json absent', async () => {
    const result = await check.run(makeCtx([]));
    expect(result.passed).toBe(true);
  });
});

describe('LY-005: Stale Pending Pairings', () => {
  const check = lyrieChecks.find(c => c.id === 'LY-005')!;

  it('fails when pending pairing older than 7 days', async () => {
    const old = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const fs = makeFs({
      files: {
        '/home/test/.lyrie/pairing.json': JSON.stringify({
          pending: [{ channel: 'telegram', senderId: '1', requestedAt: old }],
          approved: [],
        }),
      },
    });
    const result = await check.run(makeCtx([], { fs }));
    expect(result.passed).toBe(false);
  });

  it('passes when no stale pending', async () => {
    const recent = new Date().toISOString();
    const fs = makeFs({
      files: {
        '/home/test/.lyrie/pairing.json': JSON.stringify({
          pending: [{ channel: 'telegram', senderId: '1', requestedAt: recent }],
          approved: [],
        }),
      },
    });
    const result = await check.run(makeCtx([], { fs }));
    expect(result.passed).toBe(true);
  });
});

describe('LY-006: Plaintext Secrets in Over-Permissive .env', () => {
  const check = lyrieChecks.find(c => c.id === 'LY-006')!;

  it('fails for .env with API_KEY content and mode 0644', async () => {
    const config = makeEnv('/home/test/.lyrie/.env', { ANTHROPIC_API_KEY: 'sk-test' });
    const fs = makeFs({ modes: { '/home/test/.lyrie/.env': 0o644 } });
    const result = await check.run(makeCtx([config], { fs }));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('passes for .env with mode 0600', async () => {
    const config = makeEnv('/home/test/.lyrie/.env', { ANTHROPIC_API_KEY: 'sk-test' });
    const fs = makeFs({ modes: { '/home/test/.lyrie/.env': 0o600 } });
    const result = await check.run(makeCtx([config], { fs }));
    expect(result.passed).toBe(true);
  });

  it('passes for .env with no secret content', async () => {
    const config = makeEnv('/home/test/.lyrie/.env', { LYRIE_MODE: 'local' });
    const fs = makeFs({ modes: { '/home/test/.lyrie/.env': 0o644 } });
    const result = await check.run(makeCtx([config], { fs }));
    expect(result.passed).toBe(true);
  });
});

describe('LY-007: Unused Provider Keys', () => {
  const check = lyrieChecks.find(c => c.id === 'LY-007')!;

  it('fails when ANTHROPIC_API_KEY set with LYRIE_MODE=local', async () => {
    const result = await check.run(makeCtx([makeEnv('.env', {
      LYRIE_MODE: 'local',
      ANTHROPIC_API_KEY: 'sk-test',
    })]));
    expect(result.passed).toBe(false);
  });

  it('passes when LYRIE_MODE=hybrid', async () => {
    const result = await check.run(makeCtx([makeEnv('.env', {
      LYRIE_MODE: 'hybrid',
      ANTHROPIC_API_KEY: 'sk-test',
    })]));
    expect(result.passed).toBe(true);
  });
});

describe('LY-008: Remote Backend Credentials', () => {
  const check = lyrieChecks.find(c => c.id === 'LY-008')!;

  it('fails when LYRIE_BACKEND=daytona with key', async () => {
    const result = await check.run(makeCtx([makeEnv('.env', {
      LYRIE_BACKEND: 'daytona',
      DAYTONA_API_KEY: 'real-key',
    })]));
    expect(result.passed).toBe(false);
  });

  it('passes when LYRIE_BACKEND=local', async () => {
    const result = await check.run(makeCtx([makeEnv('.env', {
      LYRIE_BACKEND: 'local',
      DAYTONA_API_KEY: 'real-key',
    })]));
    expect(result.passed).toBe(true);
  });

  it('passes when value is a $VAR placeholder', async () => {
    const result = await check.run(makeCtx([makeEnv('.env', {
      LYRIE_BACKEND: 'modal',
      MODAL_TOKEN_ID: '${MODAL_TOKEN_ID}',
      MODAL_TOKEN_SECRET: '${MODAL_TOKEN_SECRET}',
    })]));
    expect(result.passed).toBe(true);
  });
});

describe('LY-009: Dry-Run Enabled', () => {
  const check = lyrieChecks.find(c => c.id === 'LY-009')!;

  it('fails when LYRIE_LOCAL_DRY_RUN=true', async () => {
    const result = await check.run(makeCtx([makeEnv('.env', { LYRIE_LOCAL_DRY_RUN: 'true' })]));
    expect(result.passed).toBe(false);
  });

  it('passes when unset', async () => {
    const result = await check.run(makeCtx([makeEnv('.env', {})]));
    expect(result.passed).toBe(true);
  });
});

describe('LY-010: WebChat Unauthenticated', () => {
  const check = lyrieChecks.find(c => c.id === 'LY-010')!;

  it('fails when WebChat is on a public host with no auth', async () => {
    const result = await check.run(makeCtx([makeEnv('.env', {
      LYRIE_WEBCHAT_HOST: '0.0.0.0',
      LYRIE_WEBCHAT_PORT: '8765',
    })]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('passes when WebChat is loopback-only', async () => {
    const result = await check.run(makeCtx([makeEnv('.env', {
      LYRIE_WEBCHAT_HOST: '127.0.0.1',
      LYRIE_WEBCHAT_PORT: '8765',
    })]));
    expect(result.passed).toBe(true);
  });

  it('passes when WebChat has auth token', async () => {
    const result = await check.run(makeCtx([makeEnv('.env', {
      LYRIE_WEBCHAT_HOST: '0.0.0.0',
      LYRIE_WEBCHAT_PORT: '8765',
      LYRIE_WEBCHAT_AUTH_TOKEN: 'real-token-not-placeholder',
    })]));
    expect(result.passed).toBe(true);
  });
});

describe('LY-011: WebChat Permissive Origins', () => {
  const check = lyrieChecks.find(c => c.id === 'LY-011')!;

  it('fails when origins is *', async () => {
    const result = await check.run(makeCtx([makeEnv('.env', {
      LYRIE_WEBCHAT_PORT: '8765',
      LYRIE_WEBCHAT_ORIGINS: '*',
    })]));
    expect(result.passed).toBe(false);
  });

  it('fails when origins is unset', async () => {
    const result = await check.run(makeCtx([makeEnv('.env', {
      LYRIE_WEBCHAT_PORT: '8765',
    })]));
    expect(result.passed).toBe(false);
  });

  it('passes when origins is explicit', async () => {
    const result = await check.run(makeCtx([makeEnv('.env', {
      LYRIE_WEBCHAT_PORT: '8765',
      LYRIE_WEBCHAT_ORIGINS: 'https://app.example.com',
    })]));
    expect(result.passed).toBe(true);
  });

  it('passes when WebChat disabled', async () => {
    const result = await check.run(makeCtx([makeEnv('.env', {})]));
    expect(result.passed).toBe(true);
  });
});

describe('LY-012: Stale Pending Edits', () => {
  const check = lyrieChecks.find(c => c.id === 'LY-012')!;

  it('fails when edit older than 24h', async () => {
    const old = new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString();
    const fs = makeFs({
      files: {
        '/home/test/.lyrie/edits.json': JSON.stringify({
          pending: [{ unifiedDiff: '...', createdAt: old }],
        }),
      },
    });
    const result = await check.run(makeCtx([], { fs }));
    expect(result.passed).toBe(false);
  });
});

describe('LY-013: Edits Store Permissions', () => {
  const check = lyrieChecks.find(c => c.id === 'LY-013')!;

  it('fails when edits.json is mode 0644', async () => {
    const fs = makeFs({ modes: { '/home/test/.lyrie/edits.json': 0o644 } });
    const result = await check.run(makeCtx([], { fs }));
    expect(result.passed).toBe(false);
  });
});

describe('LY-014: Executable Skill Files', () => {
  const check = lyrieChecks.find(c => c.id === 'LY-014')!;

  it('fails when skills dir contains .ts files', async () => {
    const fs = makeFs({
      dirEntries: {
        '/home/test/.lyrie/skills': [
          { name: 'pentest.ts', isFile: true, isDirectory: false },
          { name: 'SKILL.md', isFile: true, isDirectory: false },
        ],
      },
    });
    const result = await check.run(makeCtx([], { fs }));
    expect(result.passed).toBe(false);
  });

  it('passes when only .md files present', async () => {
    const fs = makeFs({
      dirEntries: {
        '/home/test/.lyrie/skills': [
          { name: 'SKILL.md', isFile: true, isDirectory: false },
        ],
      },
    });
    const result = await check.run(makeCtx([], { fs }));
    expect(result.passed).toBe(true);
  });
});

describe('LY-015: Skills Directory Writable', () => {
  const check = lyrieChecks.find(c => c.id === 'LY-015')!;

  it('fails when skills dir is mode 0777', async () => {
    const fs = makeFs({ modes: { '/home/test/.lyrie/skills': 0o777 } });
    const result = await check.run(makeCtx([], { fs }));
    expect(result.passed).toBe(false);
  });

  it('passes when skills dir is mode 0700', async () => {
    const fs = makeFs({ modes: { '/home/test/.lyrie/skills': 0o700 } });
    const result = await check.run(makeCtx([], { fs }));
    expect(result.passed).toBe(true);
  });
});

describe('LY-016: Migration Detected (info)', () => {
  const check = lyrieChecks.find(c => c.id === 'LY-016')!;

  it('reports info when migration manifests exist', async () => {
    const fs = makeFs({
      dirs: { '/home/test/.lyrie/migrations': ['openclaw-2026-04-28.json'] },
      files: {
        '/home/test/.lyrie/migrations/openclaw-2026-04-28.json':
          JSON.stringify({ platform: 'openclaw', itemsMigrated: 42 }),
      },
    });
    const result = await check.run(makeCtx([], { fs }));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('info');
  });
});

describe('LY-017: Migration Errors', () => {
  const check = lyrieChecks.find(c => c.id === 'LY-017')!;

  it('fails when migration manifest reports errors', async () => {
    const fs = makeFs({
      dirs: { '/home/test/.lyrie/migrations': ['hermes-2026-04-28.json'] },
      files: {
        '/home/test/.lyrie/migrations/hermes-2026-04-28.json':
          JSON.stringify({ platform: 'hermes', success: false, errors: ['db locked'] }),
      },
    });
    const result = await check.run(makeCtx([], { fs }));
    expect(result.passed).toBe(false);
  });
});

describe('LY-018: NODE_ENV Development with Channels', () => {
  const check = lyrieChecks.find(c => c.id === 'LY-018')!;

  it('fails when NODE_ENV=development with channel token', async () => {
    const result = await check.run(makeCtx([makeEnv('.env', {
      NODE_ENV: 'development',
      TELEGRAM_BOT_TOKEN: '1234:ABC',
    })]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('passes when NODE_ENV=production', async () => {
    const result = await check.run(makeCtx([makeEnv('.env', {
      NODE_ENV: 'production',
      TELEGRAM_BOT_TOKEN: '1234:ABC',
    })]));
    expect(result.passed).toBe(true);
  });

  it('passes when no channels configured', async () => {
    const result = await check.run(makeCtx([makeEnv('.env', { NODE_ENV: 'development' })]));
    expect(result.passed).toBe(true);
  });
});
