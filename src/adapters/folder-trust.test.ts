import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, mkdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { FSProvider } from '../core/fs-provider.js';
import type { Evidence, ScanContext } from '../core/types.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { markUntrustedWorkspace, trustFileDecision } from './folder-trust.js';
import { geminiWorkspaceTrusted } from './gemini.js';
import { qwenWorkspaceTrusted } from './qwen-code.js';
import { gem003 } from '../checks/gemini-cli/gem-003-overbroad-allow.js';
import { gem004 } from '../checks/gemini-cli/gem-004-yolo-guard.js';
import { qc003 } from '../checks/qwen-code/qc-003-yolo-mode.js';

let home: string;
let env: Record<string, string>;

function fsFor(): FSProvider {
  const local = new LocalFSProvider();
  return Object.assign(Object.create(local) as FSProvider, {
    homedir: () => home,
    getEnv: (k: string) => env[k],
  });
}

function write(rel: string, data: unknown): string {
  const p = join(home, rel);
  mkdirSync(join(p, '..'), { recursive: true });
  writeFileSync(p, typeof data === 'string' ? data : JSON.stringify(data));
  return p;
}

beforeEach(() => {
  home = realpathSync(mkdtempSync(join(tmpdir(), 'vaso-trust-')));
  env = {};
});
afterEach(() => rmSync(home, { recursive: true, force: true }));

describe('trustFileDecision', () => {
  it('longest matching rule wins; TRUST_PARENT covers the parent', async () => {
    const file = write('t.json', {
      [join(home, 'code', 'x')]: 'TRUST_PARENT',
      [join(home, 'code', 'evil')]: 'DO_NOT_TRUST',
    });
    expect(await trustFileDecision(fsFor(), file, join(home, 'code', 'repo'))).toBe(true);
    expect(await trustFileDecision(fsFor(), file, join(home, 'code', 'evil', 'sub'))).toBe(false);
    expect(await trustFileDecision(fsFor(), file, join(home, 'other'))).toBeUndefined();
  });

  it('a missing or malformed file decides nothing', async () => {
    expect(await trustFileDecision(fsFor(), join(home, 'none.json'), home)).toBeUndefined();
    const bad = write('bad.json', '{ nope');
    expect(await trustFileDecision(fsFor(), bad, home)).toBeUndefined();
  });
});

describe('geminiWorkspaceTrusted', () => {
  const ws = () => join(home, 'repo');

  it('folder trust is on by default: an unmatched workspace is untrusted', async () => {
    write('.gemini/trustedFolders.json', { '/elsewhere': 'TRUST_FOLDER' });
    expect(await geminiWorkspaceTrusted(fsFor(), ws())).toBe(false);
  });

  it('a TRUST_FOLDER rule trusts it', async () => {
    write('.gemini/trustedFolders.json', { [ws()]: 'TRUST_FOLDER' });
    expect(await geminiWorkspaceTrusted(fsFor(), ws())).toBe(true);
  });

  it('security.folderTrust.enabled: false in user settings trusts every workspace', async () => {
    write('.gemini/settings.json', { security: { folderTrust: { enabled: false } } });
    expect(await geminiWorkspaceTrusted(fsFor(), ws())).toBe(true);
  });

  it('GEMINI_CLI_TRUST_WORKSPACE forces the decision; GEMINI_RESTRICTED_MODE distrusts', async () => {
    env.GEMINI_CLI_TRUST_WORKSPACE = 'true';
    expect(await geminiWorkspaceTrusted(fsFor(), ws())).toBe(true);
    write('.gemini/settings.json', { security: { folderTrust: { enabled: false } } });
    env = { GEMINI_CLI_TRUST_WORKSPACE: 'false' };
    expect(await geminiWorkspaceTrusted(fsFor(), ws())).toBe(false);
    env = { GEMINI_RESTRICTED_MODE: 'true' };
    expect(await geminiWorkspaceTrusted(fsFor(), ws())).toBe(false);
  });

  it('honours GEMINI_CLI_TRUSTED_FOLDERS_PATH', async () => {
    env.GEMINI_CLI_TRUSTED_FOLDERS_PATH = write('elsewhere/trust.json', { [ws()]: 'TRUST_FOLDER' });
    expect(await geminiWorkspaceTrusted(fsFor(), ws())).toBe(true);
  });
});

describe('qwenWorkspaceTrusted', () => {
  const ws = () => join(home, 'repo');

  it('folder trust is off by default: every workspace applies', async () => {
    expect(await qwenWorkspaceTrusted(fsFor(), ws())).toBe(true);
  });

  it('once enabled, an unmatched workspace is untrusted and a rule trusts it', async () => {
    write('.qwen/settings.json', { security: { folderTrust: { enabled: true } } });
    expect(await qwenWorkspaceTrusted(fsFor(), ws())).toBe(false);
    write('.qwen/trustedFolders.json', { [ws()]: 'TRUST_FOLDER' });
    expect(await qwenWorkspaceTrusted(fsFor(), ws())).toBe(true);
  });

  it('follows QWEN_HOME for the user settings', async () => {
    env.QWEN_HOME = join(home, 'qh');
    write('qh/settings.json', { security: { folderTrust: { enabled: true } } });
    expect(await qwenWorkspaceTrusted(fsFor(), ws())).toBe(false);
  });
});

describe('workspace checks in an untrusted folder', () => {
  function projectCtx(agent: 'gemini-cli' | 'qwen-code', data: Record<string, unknown>): ScanContext {
    const dir = agent === 'gemini-cli' ? '.gemini' : '.qwen';
    const filePath = write(`repo/${dir}/settings.json`, data);
    return {
      installation: { agent, installDir: join(home, 'repo', dir), configFiles: [], profile: 'project' },
      configs: [{ raw: '', format: 'json', filePath, data }],
      platform: 'linux',
      fs: fsFor(),
    };
  }

  it('GEM-003 is inactive (info) in an untrusted workspace, critical once trusted', async () => {
    const data = { tools: { allowed: ['run_shell_command'] } };
    const untrusted = await gem003.run(projectCtx('gemini-cli', data));
    expect(untrusted.passed).toBe(false);
    expect(untrusted.severity).toBe('info');
    expect(untrusted.evidence?.every(e => e.mitigated)).toBe(true);

    write('.gemini/trustedFolders.json', { [join(home, 'repo')]: 'TRUST_FOLDER' });
    const trusted = await gem003.run(projectCtx('gemini-cli', data));
    expect(trusted.severity).toBe('critical');
    expect(trusted.evidence?.some(e => e.mitigated)).toBe(false);
  });

  it('QC-003 stays critical while Qwen folder trust is off, inactive once it is on', async () => {
    const data = { tools: { approvalMode: 'yolo' } };
    expect((await qc003.run(projectCtx('qwen-code', data))).severity).toBe('critical');
    write('.qwen/settings.json', { security: { folderTrust: { enabled: true } } });
    expect((await qc003.run(projectCtx('qwen-code', data))).severity).toBe('info');
  });

  it('a user install is never downgraded', async () => {
    const ev: Evidence[] = [{ file: 'x' }];
    const ctx = projectCtx('gemini-cli', {});
    ctx.installation.profile = undefined;
    await markUntrustedWorkspace(ctx, ev, async () => false);
    expect(ev[0].mitigated).toBeUndefined();
  });
});

describe('GEM-004', () => {
  function ctxFor(profile: string | undefined, data: Record<string, unknown>): ScanContext {
    const filePath = write(profile ? 'repo/.gemini/settings.json' : '.gemini/settings.json', data);
    return {
      installation: { agent: 'gemini-cli', installDir: join(home, profile ? 'repo/.gemini' : '.gemini'), configFiles: [], profile },
      configs: [{ raw: '', format: 'json', filePath, data }],
      platform: 'linux',
      fs: fsFor(),
    };
  }

  it('an explicit false in user settings is the default — info', async () => {
    const r = await gem004.run(ctxFor(undefined, { security: { disableYoloMode: false } }));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('info');
  });

  it('a trusted workspace turning off the user\'s guard is critical', async () => {
    write('.gemini/settings.json', { security: { disableYoloMode: true, folderTrust: { enabled: false } } });
    const r = await gem004.run(ctxFor('project', { security: { disableYoloMode: false } }));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
  });
});
