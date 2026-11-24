import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { linkSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import type { ScanContext, AgentType } from '../core/types.js';
import type { ProbeSnapshot } from '../core/snapshot-types.js';
import { SnapshotFSProvider } from '../core/snapshot-fs-provider.js';
import { captureConfigLoadErrors } from '../core/config-loader.js';
import { MemoryReader } from './memory-read.js';
import { cc012 } from '../checks/claude-code/cc-012-memory-secret-leak.js';
import { cdx007 } from '../checks/codex/cdx-007-memory-secret-leak.js';
import { opc007 } from '../checks/opencode/opc-007-memory-secret-leak.js';
import { qc010 } from '../checks/qwen-code/qc-010-memory-secrets.js';
import { ghc008 } from '../checks/copilot-cli/ghc-008-instructions-secrets.js';
import { dev007 } from '../checks/devin/dev-007-agents-md-secrets.js';
import { gem010 } from '../checks/gemini-cli/gem-010-memory-secrets.js';
import { aba012 } from '../checks/abacus/aba-012-agents-md-secrets.js';

const H = '/home/u';

function snap(files: ProbeSnapshot['files']): SnapshotFSProvider {
  return new SnapshotFSProvider({
    version: 1, probeVersion: '1.4.1', hostname: 'h', platform: 'linux', homedir: H, timestamp: '',
    privilege: { uid: 501, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
    files, directories: {}, commandOutputs: {}, env: {},
  } as ProbeSnapshot);
}

const big = { exists: true, mode: 0o644, content: '', contentOmitted: true, omitted: 'size' as const };

describe('MemoryReader', () => {
  it('reads content, notes probe-omitted files, leaves unreadable ones to CONFIG-LOAD', async () => {
    const fs = snap({
      [`${H}/a.md`]: { exists: true, mode: 0o644, content: 'hi' },
      [`${H}/big.md`]: big,
      [`${H}/fifo.md`]: { exists: true, mode: 0o644, content: '', contentOmitted: true, omitted: 'special' },
      [`${H}/denied.md`]: { exists: true, mode: 0, content: '', denied: true },
    });
    const reader = new MemoryReader(fs);
    const { loadErrors } = await captureConfigLoadErrors(async () => {
      expect(await reader.read(`${H}/a.md`)).toBe('hi');
      expect(await reader.read(`${H}/big.md`)).toBeUndefined();
      expect(await reader.read(`${H}/fifo.md`)).toBeUndefined();
      expect(await reader.read(`${H}/denied.md`)).toBeUndefined();
      expect(await reader.read(`${H}/absent.md`)).toBeUndefined();
    });
    expect(reader.unverified).toEqual([`${H}/big.md (omitted: size)`]);
    expect(reader.note()).toBe(`; ${H}/big.md (omitted: size) not verified — content not in the snapshot (checked on local scans)`);
    expect(loadErrors.map(e => e.filePath).sort()).toEqual([`${H}/denied.md`, `${H}/fifo.md`]);
    expect(new MemoryReader(fs).note()).toBe('');
  });
});

// dt25 g9-F3: a memory file that is a link into a credential store or shell
// history is not read locally, as the probe never ships it — same verdict
describe('memory checks leave a memory file linked into a store unread (local)', () => {
  const SECRET = 'mysql -u root -pQ7xLm2Kv8Zq9xR7tLm2Kv prod\nexport GITHUB_TOKEN=ghp_Ab3dE5gH7jK9mN1pQ3sT5vX7zB9dF1hJ3lN5\n';
  let home: string;
  beforeEach(() => {
    home = realpathSync(mkdtempSync(join(tmpdir(), 'memlink-')));
    mkdirSync(join(home, '.claude', 'rules'), { recursive: true });
    mkdirSync(join(home, '.codex'), { recursive: true });
    mkdirSync(join(home, '.local', 'share', 'keyrings'), { recursive: true });
    writeFileSync(join(home, '.zsh_history'), SECRET);
    writeFileSync(join(home, '.local', 'share', 'keyrings', 'login.keyring'), SECRET);
  });
  afterEach(() => rmSync(home, { recursive: true, force: true }));

  // dt25 D3: such a link is a finding of its own (warning), its content never read
  it('a symlink to a history file and a hard link to a keyring fail with a warning, unread', async () => {
    symlinkSync(join(home, '.zsh_history'), join(home, '.codex', 'AGENTS.md'));
    linkSync(join(home, '.local', 'share', 'keyrings', 'login.keyring'), join(home, '.claude', 'rules', 'h.md'));
    const fs = new HomeFS(home);
    const cdx = await cdx007.run({ installation: { agent: 'codex', installDir: join(home, '.codex'), configFiles: [] }, configs: [], platform: process.platform, fs });
    expect(cdx.passed).toBe(false);
    expect(cdx.severity).toBe('warning');
    expect(cdx.message).toBe(`${join(home, '.codex', 'AGENTS.md')} links into shell or REPL history (typed commands and passwords: any ~/.*history, .histfile, .lesshst); the agent loads its content`);
    const cc = await cc012.run({ installation: { agent: 'claude-code', installDir: join(home, '.claude'), configFiles: [] }, configs: [], platform: process.platform, fs });
    expect(cc.passed).toBe(false);
    expect(cc.severity).toBe('warning');
    expect(cc.message).toContain(`${join(home, '.claude', 'rules', 'h.md')} links into GNOME keyring credentials`);
    for (const r of [cdx, cc]) expect(JSON.stringify(r)).not.toMatch(/Q7xLm2|ghp_Ab3d/);
    // an ordinary memory file is still read
    rmSync(join(home, '.codex', 'AGENTS.md'));
    writeFileSync(join(home, '.codex', 'AGENTS.md'), SECRET);
    expect((await cdx007.run({ installation: { agent: 'codex', installDir: join(home, '.codex'), configFiles: [] }, configs: [], platform: process.platform, fs })).passed).toBe(false);
  });
});

class HomeFS extends LocalFSProvider {
  constructor(private readonly home: string) { super(); }
  override homedir(): string { return this.home; }
}

// g6-F10: a 40 MB CLAUDE.md the probe omitted for size read as clean remotely
describe('memory checks say a size-omitted file was not verified', () => {
  const cases: Array<[string, typeof cc012, AgentType, string, string]> = [
    ['CC-012', cc012, 'claude-code', `${H}/.claude`, `${H}/.claude/CLAUDE.md`],
    ['CDX-007', cdx007, 'codex', `${H}/.codex`, `${H}/.codex/AGENTS.md`],
    ['OPC-007', opc007, 'opencode', `${H}/.config/opencode`, `${H}/.config/opencode/AGENTS.md`],
    ['QC-010', qc010, 'qwen-code', `${H}/.qwen`, `${H}/.qwen/QWEN.md`],
    ['GHC-008', ghc008, 'copilot-cli', `${H}/.copilot`, `${H}/.copilot/copilot-instructions.md`],
    ['DEV-007', dev007, 'devin', `${H}/.config/devin`, `${H}/.config/devin/AGENTS.md`],
  ];
  for (const [id, check, agent, installDir, file] of cases) {
    it(id, async () => {
      const ctx: ScanContext = {
        installation: { agent, installDir, configFiles: [] }, configs: [], platform: 'linux', fs: snap({ [file]: big }),
      };
      const result = await check.run(ctx);
      expect(result.passed).toBe(true);
      expect(result.message).toContain(`${file} (omitted: size) not verified`);
    });
  }
});

// dt25 D3: the same verdict from a probe snapshot — the probe records the link
// (`symlinks`) or the hard link (`hardLinkOf`) and withholds the content
describe('memory checks report a memory file linked into a store from a snapshot', () => {
  const sensitive = { exists: true, mode: 0o644, content: '', contentOmitted: true, omitted: 'sensitive' as const };
  const privilege = { uid: 501, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] };
  function linkSnap(file: string, link: { symlink?: string; hardLinkOf?: string }): SnapshotFSProvider {
    return new SnapshotFSProvider({
      version: 1, probeVersion: '1.4.3', hostname: 'h', platform: 'linux', homedir: H, timestamp: '', privilege,
      files: { [file]: { ...sensitive, ...(link.hardLinkOf ? { hardLinkOf: link.hardLinkOf } : {}) } },
      directories: {}, commandOutputs: {}, env: {},
      ...(link.symlink ? { symlinks: { [file]: link.symlink } } : {}),
    } as ProbeSnapshot);
  }
  const cases: Array<[string, typeof cc012, AgentType, string, string]> = [
    ['CC-012', cc012, 'claude-code', `${H}/.claude`, `${H}/.claude/CLAUDE.md`],
    ['CDX-007', cdx007, 'codex', `${H}/.codex`, `${H}/.codex/AGENTS.md`],
    ['OPC-007', opc007, 'opencode', `${H}/.config/opencode`, `${H}/.config/opencode/AGENTS.md`],
    ['QC-010', qc010, 'qwen-code', `${H}/.qwen`, `${H}/.qwen/QWEN.md`],
    ['GEM-010', gem010, 'gemini-cli', `${H}/.gemini`, `${H}/.gemini/GEMINI.md`],
    ['GHC-008', ghc008, 'copilot-cli', `${H}/.copilot`, `${H}/.copilot/copilot-instructions.md`],
    ['DEV-007', dev007, 'devin', `${H}/.config/devin`, `${H}/.config/devin/AGENTS.md`],
    ['ABA-012', aba012, 'abacus', `${H}/.abacusai`, `${H}/.abacusai/AGENTS.md`],
  ];
  for (const [id, check, agent, installDir, file] of cases) {
    it(`${id}: symlink to a history file, hard link to a credentials file`, async () => {
      const run = (fs: SnapshotFSProvider) => check.run({ installation: { agent, installDir, configFiles: [] }, configs: [], platform: 'linux', fs });
      const sym = await run(linkSnap(file, { symlink: `${H}/.bash_history` }));
      expect(sym.passed).toBe(false);
      expect(sym.severity).toBe('warning');
      expect(sym.message).toBe(`${file} links into shell or REPL history (typed commands and passwords: any ~/.*history, .histfile, .lesshst); the agent loads its content`);
      expect(sym.evidence).toEqual([{ file, detail: sym.message }]);
      const hard = await run(linkSnap(file, { hardLinkOf: `${H}/.vault-token` }));
      expect(hard.passed).toBe(false);
      expect(hard.severity).toBe('warning');
      expect(hard.message).toMatch(/links into credentials file \(\.vault-token/);
    });
  }

  it('a withheld file whose link the snapshot does not name is "not verified" (a pass, as for other omitted content)', async () => {
    const r = await cdx007.run({ installation: { agent: 'codex', installDir: `${H}/.codex`, configFiles: [] }, configs: [], platform: 'linux', fs: linkSnap(`${H}/.codex/AGENTS.md`, {}) });
    expect(r.passed).toBe(true);
    expect(r.message).toContain(`${H}/.codex/AGENTS.md (omitted: sensitive) not verified`);
  });

  it('secrets in another memory file keep their severity beside a link', async () => {
    const fs = new SnapshotFSProvider({
      version: 1, probeVersion: '1.4.3', hostname: 'h', platform: 'linux', homedir: H, timestamp: '', privilege,
      files: {
        [`${H}/.codex/AGENTS.override.md`]: { exists: true, mode: 0o644, content: 'export GITHUB_TOKEN=ghp_Ab3dE5gH7jK9mN1pQ3sT5vX7zB9dF1hJ3lN5\n' },
        [`${H}/.codex/AGENTS.md`]: sensitive,
      },
      directories: {}, commandOutputs: {}, env: {}, symlinks: { [`${H}/.codex/AGENTS.md`]: `${H}/.zsh_history` },
    } as ProbeSnapshot);
    const r = await cdx007.run({ installation: { agent: 'codex', installDir: `${H}/.codex`, configFiles: [] }, configs: [], platform: 'linux', fs });
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
    expect(r.evidence).toHaveLength(2);
    expect(r.message).toMatch(/^Found 1 potential secret\(s\) in Codex memory files; .*AGENTS\.md links into shell or REPL history/);
  });
});
