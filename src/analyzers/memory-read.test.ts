import { describe, it, expect } from 'vitest';
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
