import { describe, it, expect, vi } from 'vitest';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider, DirentInfo } from '../../core/fs-provider.js';
import { lyrieChecks } from './index.js';

const HOME = '/home/test';
const STATE = `${HOME}/.lyrie`;
const CHECKOUT = `${HOME}/lyrie-ai`;
const ENV_PATH = `${CHECKOUT}/.env`;
const PKG = JSON.stringify({ name: 'lyrie-agent', version: '3.4.0' });

/** `cp .env.example .env` of Lyrie 3.4.0 (values as shipped upstream). */
const ENV_EXAMPLE: Record<string, string> = {
  ANTHROPIC_API_KEY: 'sk-ant-...',
  OPENAI_API_KEY: 'sk-proj-...',
  GOOGLE_API_KEY: 'AIza...',
  XAI_API_KEY: 'xai-...',
  MINIMAX_API_KEY: '',
  MINIMAX_GROUP_ID: '',
  OLLAMA_BASE_URL: 'http://localhost:11434',
  TELEGRAM_BOT_TOKEN: '',
  DISCORD_BOT_TOKEN: '',
  SLACK_BOT_TOKEN: '',
  LYRIE_MODE: 'hybrid',
  LYRIE_PREFER_LOCAL: 'false',
  LYRIE_MEMORY_PATH: '',
  LYRIE_LOG_LEVEL: 'info',
  LYRIE_SHIELD_MODE: 'active',
  NODE_ENV: 'development',
};

function makeEnv(data: Record<string, unknown>, filePath = ENV_PATH): ParsedConfig {
  return {
    raw: Object.entries(data).map(([k, v]) => `${k}=${v}`).join('\n'),
    format: 'env',
    filePath,
    data,
  };
}

function makeJson(filePath: string, data: Record<string, unknown>): ParsedConfig {
  return { raw: JSON.stringify(data), format: 'json', filePath, data };
}

interface FsOverrides {
  files?: Record<string, string>;
  modes?: Record<string, number>;
  dirs?: Record<string, string[]>;
  dirEntries?: Record<string, DirentInfo[]>;
}

function makeFs(o: FsOverrides = {}): FSProvider {
  const isAncestor = (p: string) =>
    [...Object.keys(o.modes ?? {}), ...Object.keys(o.files ?? {}), ...Object.keys(o.dirs ?? {})]
      .some(k => k.startsWith(p === '/' ? p : `${p}/`));
  const exists = (p: string) =>
    p in (o.files ?? {}) || p in (o.modes ?? {}) || p in (o.dirs ?? {}) || p in (o.dirEntries ?? {});

  return {
    access: vi.fn(async (p: string) => exists(p)),
    stat: vi.fn(async (p: string) => {
      if (!exists(p) && !isAncestor(p)) throw new Error(`ENOENT ${p}`);
      return {
        // Ancestors of known paths are ordinary traversable dirs (parent-dir mitigation)
        mode: o.modes?.[p] ?? (isAncestor(p) ? 0o755 : 0o600),
        isFile: () => !(p in (o.dirs ?? {})),
        isDirectory: () => p in (o.dirs ?? {}) || p in (o.dirEntries ?? {}),
      };
    }),
    readFile: vi.fn(async (p: string) => {
      const v = o.files?.[p];
      if (v == null) throw new Error(`ENOENT ${p}`);
      return v;
    }),
    readdir: vi.fn(async (p: string) => {
      if (!(p in (o.dirs ?? {}))) throw new Error(`ENOENT ${p}`);
      return o.dirs![p];
    }),
    readdirEntries: vi.fn(async (p: string) => o.dirEntries?.[p] ?? []),
    realpath: vi.fn(async (p: string) => p),
    exec: vi.fn(),
    execSync: vi.fn(() => { throw new Error('not found'); }),
    homedir: () => HOME,
    getEnv: vi.fn(() => undefined),
    platform: 'linux',
  } as unknown as FSProvider;
}

function makeCtx(configs: ParsedConfig[], opts: { installDir?: string; fs?: FSProvider } = {}): ScanContext {
  const installDir = opts.installDir ?? CHECKOUT;
  const installation: AgentInstallation = {
    agent: 'lyrie',
    installDir,
    skillsDir: `${STATE}/skills`,
    configFiles: configs,
  };
  return {
    installation,
    configs,
    platform: 'linux',
    fs: opts.fs ?? makeFs(),
  };
}

const check = (id: string) => lyrieChecks.find(c => c.id === id)!;

describe('Lyrie checks', () => {
  it('exports 20 checks', () => {
    expect(lyrieChecks).toHaveLength(20);
  });

  it('all checks have lyrie category and supportedAgents', () => {
    for (const c of lyrieChecks) {
      expect(c.category).toBe('lyrie');
      expect(c.supportedAgents).toContain('lyrie');
    }
  });

  it('all check IDs match LY-NNN and are unique', () => {
    const ids = lyrieChecks.map(c => c.id);
    for (const id of ids) expect(id).toMatch(/^LY-0\d{2}$/);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('no check throws on odd config shapes (JSON key store, null/array values, empty data)', async () => {
    const configs = [
      makeEnv({}),
      makeEnv({ LYRIE_WEBCHAT_ENABLED: 'true', LYRIE_TELEGRAM_TOKEN: '1:x' }),
      makeJson(`${STATE}/config.json`, { ANTHROPIC_API_KEY: 'sk-ant-api03-x', nested: { a: [1, null] }, list: [] }),
      { raw: '', format: 'env', filePath: `${HOME}/lyrie/.env`, data: { NODE_ENV: 5 as unknown as string } } as ParsedConfig,
    ];
    const fs = makeFs({
      files: {
        [`${STATE}/pairing.json`]: '{"pending":[null,1,"x",{"requestedAt":5}],"approved":null}',
        [`${STATE}/edits.json`]: '{"pending":{"not":"array"}}',
        [`${STATE}/migrations/a.json`]: 'null',
        [`${STATE}/migrations/b.json`]: '[1,2]',
      },
      dirs: { [`${STATE}/migrations`]: ['a.json', 'b.json'], [`${STATE}/memory`]: [] },
    });
    for (const c of lyrieChecks) {
      await expect(c.run(makeCtx(configs, { fs }))).resolves.toHaveProperty('id', c.id);
    }
  });
});

describe('LY-001: Shield mode passive', () => {
  it('reports passive as info (not enforced in 3.4.0)', async () => {
    const r = await check('LY-001').run(makeCtx([makeEnv({ ...ENV_EXAMPLE, LYRIE_SHIELD_MODE: 'passive' })]));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('info');
    expect(r.fixable).toBe(true);
  });

  it('flags an invalid mode (startup would fail)', async () => {
    const r = await check('LY-001').run(makeCtx([makeEnv({ LYRIE_SHIELD_MODE: 'off' })]));
    expect(r.passed).toBe(false);
    expect(r.evidence![0].detail).toMatch(/Invalid/);
  });

  it('passes for the .env.example default (active)', async () => {
    const r = await check('LY-001').run(makeCtx([makeEnv(ENV_EXAMPLE)]));
    expect(r.passed).toBe(true);
  });

  it('ignores the Python CLI JSON key store', async () => {
    const r = await check('LY-001').run(makeCtx([makeJson(`${STATE}/config.json`, { LYRIE_SHIELD_MODE: 'passive' })]));
    expect(r.passed).toBe(true);
  });
});

describe('LY-002: Rust Shield binary not built', () => {
  const files = { [`${CHECKOUT}/package.json`]: PKG };

  it('fails when the checkout has no target/{release,debug}/lyrie-shield', async () => {
    const r = await check('LY-002').run(makeCtx([], { fs: makeFs({ files }) }));
    expect(r.passed).toBe(false);
    expect(r.evidence![0].file).toBe(`${CHECKOUT}/packages/shield/target/release/lyrie-shield`);
  });

  it('passes when the release binary is built (PATH is irrelevant)', async () => {
    const fs = makeFs({ files, modes: { [`${CHECKOUT}/packages/shield/target/release/lyrie-shield`]: 0o755 } });
    const r = await check('LY-002').run(makeCtx([], { fs }));
    expect(r.passed).toBe(true);
  });

  it('passes when only the debug binary is built', async () => {
    const fs = makeFs({ files, modes: { [`${CHECKOUT}/packages/shield/target/debug/lyrie-shield`]: 0o755 } });
    const r = await check('LY-002').run(makeCtx([], { fs }));
    expect(r.passed).toBe(true);
  });

  it('is not applicable without a checkout (state dir only)', async () => {
    const r = await check('LY-002').run(makeCtx([], { installDir: STATE, fs: makeFs() }));
    expect(r.passed).toBe(true);
  });
});

describe('LY-003: DM policy open on live channel', () => {
  it('fails for Telegram (LYRIE_TELEGRAM_TOKEN) with no policy and no allowlist', async () => {
    const r = await check('LY-003').run(makeCtx([makeEnv({ ...ENV_EXAMPLE, LYRIE_TELEGRAM_TOKEN: '7000000001:AAtest' })]));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
    expect(r.evidence![0].detail).toMatch(/telegram/);
  });

  it('counts a ${VAR} token as enabled (Bun expands it at startup)', async () => {
    const r = await check('LY-003').run(makeCtx([makeEnv({ LYRIE_DISCORD_TOKEN: '${DISCORD_TOKEN}' })]));
    expect(r.passed).toBe(false);
  });

  it('passes for Telegram with an allowlist (enforced by its AuthChecker)', async () => {
    const r = await check('LY-003').run(makeCtx([makeEnv({ LYRIE_TELEGRAM_TOKEN: '1:x', LYRIE_TELEGRAM_USERS: '12345' })]));
    expect(r.passed).toBe(true);
  });

  it('fails for Discord with an allowlist but open policy (allowlist not enforced)', async () => {
    const r = await check('LY-003').run(makeCtx([makeEnv({ LYRIE_DISCORD_TOKEN: 'tok', LYRIE_DISCORD_USERS: '1' })]));
    expect(r.passed).toBe(false);
  });

  it('treats an invalid policy as open', async () => {
    const r = await check('LY-003').run(makeCtx([makeEnv({ LYRIE_SLACK_BOT_TOKEN: 'xoxb-1', LYRIE_SLACK_DM_POLICY: 'strict' })]));
    expect(r.passed).toBe(false);
    expect(r.evidence![0].detail).toMatch(/invalid/);
  });

  it('passes with pairing or closed policy', async () => {
    const r = await check('LY-003').run(makeCtx([makeEnv({
      LYRIE_TELEGRAM_TOKEN: '1:x', LYRIE_TELEGRAM_DM_POLICY: 'pairing',
      LYRIE_MATRIX_HOMESERVER: 'https://m.example', LYRIE_MATRIX_TOKEN: 't', LYRIE_MATRIX_DM_POLICY: 'CLOSED',
    })]));
    expect(r.passed).toBe(true);
  });

  it('requires every enable key (Matrix needs homeserver + token)', async () => {
    const r = await check('LY-003').run(makeCtx([makeEnv({ LYRIE_MATRIX_TOKEN: 't' })]));
    expect(r.passed).toBe(true);
  });

  it('ignores the core-only TELEGRAM_BOT_TOKEN/DISCORD_BOT_TOKEN keys (they start no channel)', async () => {
    const r = await check('LY-003').run(makeCtx([makeEnv({ TELEGRAM_BOT_TOKEN: '1:x', DISCORD_BOT_TOKEN: 'y', SLACK_BOT_TOKEN: 'z' })]));
    expect(r.passed).toBe(true);
  });

  it('passes for the untouched .env.example', async () => {
    const r = await check('LY-003').run(makeCtx([makeEnv(ENV_EXAMPLE)]));
    expect(r.passed).toBe(true);
  });
});

describe('LY-004: pairing store permissions', () => {
  it('fails when pairing.json is world-readable', async () => {
    const fs = makeFs({ modes: { [`${STATE}/pairing.json`]: 0o644 } });
    const r = await check('LY-004').run(makeCtx([], { fs }));
    expect(r.passed).toBe(false);
  });

  it('passes for the upstream 0600 mode and for group-only access', async () => {
    for (const mode of [0o600, 0o660]) {
      const fs = makeFs({ modes: { [`${STATE}/pairing.json`]: mode } });
      const r = await check('LY-004').run(makeCtx([], { fs }));
      expect(r.passed).toBe(true);
    }
  });

  it('passes when pairing.json is absent', async () => {
    const r = await check('LY-004').run(makeCtx([], { fs: makeFs() }));
    expect(r.passed).toBe(true);
  });
});

describe('LY-005: stale pending pairings', () => {
  it('fails when a pending pairing is older than 7 days', async () => {
    const old = new Date(Date.now() - 10 * 86400_000).toISOString();
    const fs = makeFs({ files: { [`${STATE}/pairing.json`]: JSON.stringify({
      pending: [{ channel: 'telegram', senderId: '1', code: 'ABCD-EFGH', requestedAt: old }], approved: [],
    }) } });
    const r = await check('LY-005').run(makeCtx([], { fs }));
    expect(r.passed).toBe(false);
  });

  it('passes for fresh requests', async () => {
    const fs = makeFs({ files: { [`${STATE}/pairing.json`]: JSON.stringify({
      pending: [{ channel: 'telegram', senderId: '1', requestedAt: new Date().toISOString() }], approved: [],
    }) } });
    const r = await check('LY-005').run(makeCtx([], { fs }));
    expect(r.passed).toBe(true);
  });
});

describe('LY-006: secrets file readable by other users', () => {
  const live = { ...ENV_EXAMPLE, ANTHROPIC_API_KEY: 'sk-ant-api03-test', LYRIE_TELEGRAM_TOKEN: '7000000001:AAtest' };

  it('fails for a 0664 checkout .env holding real keys (cp .env.example default)', async () => {
    const fs = makeFs({ modes: { [ENV_PATH]: 0o664 } });
    const r = await check('LY-006').run(makeCtx([makeEnv(live)], { fs }));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
    expect(r.evidence![0].detail).toMatch(/ANTHROPIC_API_KEY/);
    expect(r.evidence![0].detail).not.toMatch(/OPENAI_API_KEY/); // placeholder sk-proj-...
  });

  it('fails for a readable ~/.lyrie/config.json (Python CLI key store)', async () => {
    const path = `${STATE}/config.json`;
    const fs = makeFs({ modes: { [path]: 0o644 } });
    const r = await check('LY-006').run(makeCtx([makeJson(path, { ANTHROPIC_API_KEY: 'sk-ant-api03-test', GITHUB_TOKEN: 'ghp_x' })], { fs }));
    expect(r.passed).toBe(false);
  });

  it('passes for 0600 files', async () => {
    const fs = makeFs({ modes: { [ENV_PATH]: 0o600 } });
    const r = await check('LY-006').run(makeCtx([makeEnv(live)], { fs }));
    expect(r.passed).toBe(true);
  });

  it('passes for a readable .env holding only .env.example placeholders', async () => {
    const fs = makeFs({ modes: { [ENV_PATH]: 0o644 } });
    const r = await check('LY-006').run(makeCtx([makeEnv(ENV_EXAMPLE)], { fs }));
    expect(r.passed).toBe(true);
  });

  it('downgrades to info when the parent directory blocks other users', async () => {
    const fs = makeFs({ modes: { [ENV_PATH]: 0o644, [CHECKOUT]: 0o700 } });
    const r = await check('LY-006').run(makeCtx([makeEnv(live)], { fs }));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('info');
  });
});

describe('LY-007: local-only mode not enforced', () => {
  it('fails for LYRIE_MODE=local with a real cloud key', async () => {
    const r = await check('LY-007').run(makeCtx([makeEnv({ LYRIE_MODE: 'local', ANTHROPIC_API_KEY: 'sk-ant-api03-test' })]));
    expect(r.passed).toBe(false);
  });

  it('fails for LYRIE_REQUIRE_LOCAL=true with a real cloud key', async () => {
    const r = await check('LY-007').run(makeCtx([makeEnv({ LYRIE_REQUIRE_LOCAL: 'true', OPENAI_API_KEY: 'sk-proj-abc' })]));
    expect(r.passed).toBe(false);
  });

  it('passes for hybrid mode and for placeholder keys', async () => {
    expect((await check('LY-007').run(makeCtx([makeEnv({ ...ENV_EXAMPLE, ANTHROPIC_API_KEY: 'sk-ant-real' })]))).passed).toBe(true);
    expect((await check('LY-007').run(makeCtx([makeEnv({ ...ENV_EXAMPLE, LYRIE_MODE: 'local' })]))).passed).toBe(true);
  });
});

describe('LY-008: remote scan backend credentials', () => {
  it('fails for daytona with a plaintext key', async () => {
    const r = await check('LY-008').run(makeCtx([makeEnv({ LYRIE_BACKEND: 'daytona', DAYTONA_API_KEY: 'dtn_abc' })]));
    expect(r.passed).toBe(false);
  });

  it('passes for local backend and $VAR references', async () => {
    expect((await check('LY-008').run(makeCtx([makeEnv({ LYRIE_BACKEND: 'local', DAYTONA_API_KEY: 'dtn_abc' })]))).passed).toBe(true);
    expect((await check('LY-008').run(makeCtx([makeEnv({ LYRIE_BACKEND: 'modal', MODAL_TOKEN_ID: '${MODAL_ID}' })]))).passed).toBe(true);
  });
});

describe('LY-009: dry-run', () => {
  it('fails for LYRIE_LOCAL_DRY_RUN=1', async () => {
    const r = await check('LY-009').run(makeCtx([makeEnv({ LYRIE_LOCAL_DRY_RUN: '1' })]));
    expect(r.passed).toBe(false);
    expect(r.fixable).toBe(true);
  });

  it('passes when unset', async () => {
    const r = await check('LY-009').run(makeCtx([makeEnv(ENV_EXAMPLE)]));
    expect(r.passed).toBe(true);
  });
});

describe('LY-010: WebChat on non-loopback host without token', () => {
  it('fails for LYRIE_WEBCHAT_ENABLED=true + HOST=0.0.0.0 without LYRIE_WEBCHAT_TOKEN', async () => {
    const r = await check('LY-010').run(makeCtx([makeEnv({ LYRIE_WEBCHAT_ENABLED: 'true', LYRIE_WEBCHAT_HOST: '0.0.0.0' })]));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('warning');
    expect(r.evidence![0].detail).toMatch(/0\.0\.0\.0:7777/);
  });

  it('passes when WebChat is not enabled even if host/port are set', async () => {
    const r = await check('LY-010').run(makeCtx([makeEnv({ LYRIE_WEBCHAT_HOST: '0.0.0.0', LYRIE_WEBCHAT_PORT: '7777' })]));
    expect(r.passed).toBe(true);
  });

  it('passes with LYRIE_WEBCHAT_TOKEN or a loopback host', async () => {
    expect((await check('LY-010').run(makeCtx([makeEnv({ LYRIE_WEBCHAT_ENABLED: 'true', LYRIE_WEBCHAT_HOST: '0.0.0.0', LYRIE_WEBCHAT_TOKEN: 'long-random' })]))).passed).toBe(true);
    expect((await check('LY-010').run(makeCtx([makeEnv({ LYRIE_WEBCHAT_ENABLED: 'true' })]))).passed).toBe(true);
  });

  it('does not honour the non-existent LYRIE_WEBCHAT_AUTH_TOKEN', async () => {
    const r = await check('LY-010').run(makeCtx([makeEnv({ LYRIE_WEBCHAT_ENABLED: 'true', LYRIE_WEBCHAT_HOST: '10.0.0.5', LYRIE_WEBCHAT_AUTH_TOKEN: 'x' })]));
    expect(r.passed).toBe(false);
  });
});

describe('LY-011: WebChat origins', () => {
  it('fails when enabled with origins unset or "*"', async () => {
    expect((await check('LY-011').run(makeCtx([makeEnv({ LYRIE_WEBCHAT_ENABLED: 'true' })]))).passed).toBe(false);
    expect((await check('LY-011').run(makeCtx([makeEnv({ LYRIE_WEBCHAT_ENABLED: 'true', LYRIE_WEBCHAT_ORIGINS: 'https://a.example, *' })]))).passed).toBe(false);
  });

  it('passes with explicit origins or WebChat disabled', async () => {
    expect((await check('LY-011').run(makeCtx([makeEnv({ LYRIE_WEBCHAT_ENABLED: 'true', LYRIE_WEBCHAT_ORIGINS: 'https://chat.example.com' })]))).passed).toBe(true);
    expect((await check('LY-011').run(makeCtx([makeEnv({ LYRIE_WEBCHAT_PORT: '7777' })]))).passed).toBe(true);
  });

  it('is guidance-only (no guessed origin is written)', async () => {
    const r = await check('LY-011').run(makeCtx([makeEnv({ LYRIE_WEBCHAT_ENABLED: 'true' })]));
    expect(r.fixable).toBeFalsy();
    expect(check('LY-011').fix).toBeUndefined();
  });
});

describe('LY-012: stale pending edits', () => {
  it('fails when an edit plan is older than 24h', async () => {
    const old = new Date(Date.now() - 48 * 3600_000).toISOString();
    const fs = makeFs({ files: { [`${STATE}/edits.json`]: JSON.stringify({ applied: [], pending: [{ id: 'p1', path: '/tmp/x', createdAt: old }] }) } });
    const r = await check('LY-012').run(makeCtx([], { fs }));
    expect(r.passed).toBe(false);
    expect(r.fixDescription).toMatch(/bun run edits/);
  });
});

describe('LY-013: edit ledger permissions', () => {
  it('fails when edits.json is world-readable', async () => {
    const fs = makeFs({ modes: { [`${STATE}/edits.json`]: 0o644 } });
    expect((await check('LY-013').run(makeCtx([], { fs }))).passed).toBe(false);
  });

  it('passes for 0600', async () => {
    const fs = makeFs({ modes: { [`${STATE}/edits.json`]: 0o600 } });
    expect((await check('LY-013').run(makeCtx([], { fs }))).passed).toBe(true);
  });
});

describe('LY-014: executable code in skills', () => {
  it('reports scripts as info', async () => {
    const fs = makeFs({
      dirs: { [`${STATE}/skills`]: [] },
      dirEntries: { [`${STATE}/skills`]: [
        { name: 'SKILL.md', isFile: true, isDirectory: false },
        { name: 'run.sh', isFile: true, isDirectory: false },
      ] },
    });
    const r = await check('LY-014').run(makeCtx([], { fs }));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('info');
  });

  it('passes for SKILL.md and migrated JSON only', async () => {
    const fs = makeFs({
      dirs: { [`${STATE}/skills`]: [] },
      dirEntries: { [`${STATE}/skills`]: [
        { name: 'SKILL.md', isFile: true, isDirectory: false },
        { name: 'nanobot-tools.json', isFile: true, isDirectory: false },
      ] },
    });
    expect((await check('LY-014').run(makeCtx([], { fs }))).passed).toBe(true);
  });
});

describe('LY-015: skills directory world-writable', () => {
  it('fails for 0777', async () => {
    const fs = makeFs({ dirs: { [`${STATE}/skills`]: [] }, modes: { [`${STATE}/skills`]: 0o777 } });
    expect((await check('LY-015').run(makeCtx([], { fs }))).passed).toBe(false);
  });

  it('passes for the umask-default 0775 (group write within a private group)', async () => {
    const fs = makeFs({ dirs: { [`${STATE}/skills`]: [] }, modes: { [`${STATE}/skills`]: 0o775 } });
    expect((await check('LY-015').run(makeCtx([], { fs }))).passed).toBe(true);
  });
});

describe('LY-016/LY-017: migrations', () => {
  const manifest = (over: Record<string, unknown>) => JSON.stringify({
    platform: 'nanobot', success: true, itemsMigrated: 2, errors: [], warnings: ['w'],
    manifest: {}, duration: 1, migratedAt: '2026-01-01T00:00:00.000Z', lyrieVersion: '0.1.0', ...over,
  });

  it('LY-016 reports the imported platform (info)', async () => {
    const fs = makeFs({
      dirs: { [`${STATE}/migrations`]: ['nanobot-1.json'] },
      files: { [`${STATE}/migrations/nanobot-1.json`]: manifest({}) },
    });
    const r = await check('LY-016').run(makeCtx([], { fs }));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('info');
    expect(r.evidence![0].detail).toMatch(/nanobot/);
  });

  it('LY-017 passes a clean manifest and fails one with errors', async () => {
    const clean = makeFs({
      dirs: { [`${STATE}/migrations`]: ['a.json'] },
      files: { [`${STATE}/migrations/a.json`]: manifest({}) },
    });
    expect((await check('LY-017').run(makeCtx([], { fs: clean }))).passed).toBe(true);

    const bad = makeFs({
      dirs: { [`${STATE}/migrations`]: ['a.json'] },
      files: { [`${STATE}/migrations/a.json`]: manifest({ success: false, errors: ['boom'] }) },
    });
    const r = await check('LY-017').run(makeCtx([], { fs: bad }));
    expect(r.passed).toBe(false);
    expect(r.fixDescription).toMatch(/bun run migrate/);
  });
});

describe('LY-018: NODE_ENV=development disables Shield SSRF guard', () => {
  it('fails for the .env.example default', async () => {
    const r = await check('LY-018').run(makeCtx([makeEnv(ENV_EXAMPLE)]));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('warning');
    expect(r.fixable).toBe(true);
  });

  it('passes for production or unset', async () => {
    expect((await check('LY-018').run(makeCtx([makeEnv({ ...ENV_EXAMPLE, NODE_ENV: 'production' })]))).passed).toBe(true);
    expect((await check('LY-018').run(makeCtx([makeEnv({ LYRIE_MODE: 'hybrid' })]))).passed).toBe(true);
  });
});

describe('layered .env files (Bun precedence)', () => {
  it('judges a key in the file that wins: .env.local overrides .env', async () => {
    const base = makeEnv({ ...ENV_EXAMPLE, NODE_ENV: 'development' });
    const local = makeEnv({ NODE_ENV: 'production', LYRIE_DISCORD_TOKEN: 'tok', LYRIE_DISCORD_DM_POLICY: 'open' }, `${CHECKOUT}/.env.local`);
    expect((await check('LY-018').run(makeCtx([base, local]))).passed).toBe(true);
    const ly003 = await check('LY-003').run(makeCtx([base, local]));
    expect(ly003.passed).toBe(false);
    expect(ly003.evidence![0].file).toBe(`${CHECKOUT}/.env.local`);
  });

  it('a development value only in .env.development.local still fires, attributed to that file', async () => {
    const base = makeEnv({ NODE_ENV: 'production' });
    const devLocal = makeEnv({ NODE_ENV: 'development' }, `${CHECKOUT}/.env.development.local`);
    const r = await check('LY-018').run(makeCtx([base, devLocal]));
    expect(r.passed).toBe(false);
    expect(r.evidence![0].file).toBe(`${CHECKOUT}/.env.development.local`);
  });
});

describe('LY-019: skill sandbox root over-broad', () => {
  it('fails for /, ~, $HOME and /home', async () => {
    for (const root of ['/', '~', HOME, `${HOME}/`, '/home', '$HOME', '${HOME}']) {
      const r = await check('LY-019').run(makeCtx([makeEnv({ LYRIE_FS_ROOT: root })]));
      expect(r.passed, root).toBe(false);
    }
  });

  it('passes for unset or a dedicated directory', async () => {
    expect((await check('LY-019').run(makeCtx([makeEnv(ENV_EXAMPLE)]))).passed).toBe(true);
    expect((await check('LY-019').run(makeCtx([makeEnv({ LYRIE_FS_ROOT: `${HOME}/lyrie-sandbox` })]))).passed).toBe(true);
  });
});

describe('LY-020: conversation memory readable by other users', () => {
  const db = `${STATE}/memory/lyrie-memory.db`;

  it('fails for a world-readable plaintext memory db', async () => {
    const fs = makeFs({ dirs: { [`${STATE}/memory`]: ['lyrie-memory.db'] }, modes: { [db]: 0o644 } });
    const r = await check('LY-020').run(makeCtx([makeEnv(ENV_EXAMPLE)], { fs }));
    expect(r.passed).toBe(false);
  });

  it('is mitigated (info) when ~/.lyrie is 0700', async () => {
    const fs = makeFs({ dirs: { [`${STATE}/memory`]: ['lyrie-memory.db'] }, modes: { [db]: 0o644, [STATE]: 0o700 } });
    const r = await check('LY-020').run(makeCtx([makeEnv(ENV_EXAMPLE)], { fs }));
    expect(r.severity).toBe('info');
  });

  it('passes when LYRIE_MEMORY_KEY encrypts memory at rest', async () => {
    const fs = makeFs({ dirs: { [`${STATE}/memory`]: ['lyrie-memory.db'] }, modes: { [db]: 0o644 } });
    const r = await check('LY-020').run(makeCtx([makeEnv({ LYRIE_MEMORY_KEY: 'a2V5a2V5a2V5' })], { fs }));
    expect(r.passed).toBe(true);
  });

  it('passes when no memory store exists', async () => {
    expect((await check('LY-020').run(makeCtx([], { fs: makeFs() }))).passed).toBe(true);
  });
});

describe('fixes write only upstream keys into the affected .env', () => {
  it('LY-018 sets NODE_ENV=production in the development .env only; LY-009/LY-001 target their own files', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vaso-lyrie-'));
    try {
      const prod = join(dir, 'prod.env');
      const dev = join(dir, 'dev.env');
      await writeFile(prod, 'NODE_ENV=production\nLYRIE_LOCAL_DRY_RUN=1\n');
      await writeFile(dev, '# Node environment\nNODE_ENV=development\nLYRIE_SHIELD_MODE=passive\n');
      const configs = [
        makeEnv({ NODE_ENV: 'production', LYRIE_LOCAL_DRY_RUN: '1' }, prod),
        makeEnv({ NODE_ENV: 'development', LYRIE_SHIELD_MODE: 'passive' }, dev),
      ];

      expect((await check('LY-018').fix!(makeCtx(configs))).applied).toBe(true);
      expect((await check('LY-009').fix!(makeCtx(configs))).applied).toBe(true);
      expect((await check('LY-001').fix!(makeCtx(configs))).applied).toBe(true);

      expect(await readFile(prod, 'utf-8')).toBe('NODE_ENV=production\nLYRIE_LOCAL_DRY_RUN=false\n');
      expect(await readFile(dev, 'utf-8')).toBe('# Node environment\nNODE_ENV=production\nLYRIE_SHIELD_MODE=active\n');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('fixes never write into the Python CLI JSON key store', async () => {
    const configs = [makeJson(`${STATE}/config.json`, { NODE_ENV: 'development' })];
    const r = await check('LY-018').fix!(makeCtx(configs));
    expect(r.applied).toBe(false);
  });
});
