import { describe, it, expect, vi } from 'vitest';
import type { AgentType, CheckModule, ScanContext } from '../core/types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { memorySecretSeverity, scanMemorySecrets } from './memory-secrets.js';
import { cc012 } from '../checks/claude-code/cc-012-memory-secret-leak.js';
import { cdx007 } from '../checks/codex/cdx-007-memory-secret-leak.js';
import { opc007 } from '../checks/opencode/opc-007-memory-secret-leak.js';
import { gem010 } from '../checks/gemini-cli/gem-010-memory-secrets.js';
import { qc010 } from '../checks/qwen-code/qc-010-memory-secrets.js';
import { ghc008 } from '../checks/copilot-cli/ghc-008-instructions-secrets.js';
import { dev007 } from '../checks/devin/dev-007-agents-md-secrets.js';

// Shapes of current OpenAI keys (fake bodies)
const PROJ = 'sk-proj-' + 'Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z_Ab3dEf6hIj9kLm2-nOp5qRs8tUv';
const SVCACCT = 'sk-svcacct-' + 'Zy9xWv8uTs7rQp6oNm5lKj4iHg3fEd2cBa1_Zy9xWv8uTs7rQp6';
const ADMIN = 'sk-admin-' + 'Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G5h6J7k8L9z0X1c2V3b4';
const LEGACY = 'sk-' + 'T3BlbkFJ'.repeat(6);

describe('scanMemorySecrets', () => {
  it.each([PROJ, SVCACCT, ADMIN, LEGACY])('recognises %s as an OpenAI key (critical)', (key) => {
    const ev = scanMemorySecrets('/r/CLAUDE.md', `Deploy with OPENAI_API_KEY=${key}\n`);
    expect(ev).toHaveLength(1);
    expect(ev[0].detail).toBe('Plaintext OpenAI API key in memory file');
    expect(memorySecretSeverity(ev)).toBe('critical');
  });

  it('reports one item per line even when several formats overlap', () => {
    const ev = scanMemorySecrets('/r/AGENTS.md', `ghp_${'a1B2'.repeat(10)}`);
    expect(ev).toHaveLength(1);
  });

  it('does not read a key inside another word', () => {
    expect(scanMemorySecrets('/r/AGENTS.md', 'mount disk-0123456789abcdefghijklmnop')).toEqual([]);
  });

  it('skips documentation placeholders', () => {
    expect(scanMemorySecrets('/r/AGENTS.md', 'export OPENAI_API_KEY=sk-proj-your-api-key-goes-here-xxxx')).toEqual([]);
  });

  it('a high-entropy string with no known prefix is a warning', () => {
    const ev = scanMemorySecrets('/r/AGENTS.md', 'token: "MuK5z1eQATYLId92VoWwSfcrv7qmRBnh6yOHkxsjtP3abFCNg4lXGi0E"');
    expect(ev).toHaveLength(1);
    expect(ev[0].detail).toMatch(/High-entropy/);
    expect(memorySecretSeverity(ev)).toBe('warning');
  });

  it('a mitigated credential does not make the result critical', () => {
    const ev = scanMemorySecrets('/r/AGENTS.md', `key ${PROJ}`).map(e => Object.assign(e, { mitigated: true }));
    expect(memorySecretSeverity(ev)).toBe('warning');
  });
});

// Every memory-file check uses the same formats and the same tiering
const MODULES: Array<[CheckModule, AgentType, string]> = [
  [cc012, 'claude-code', '/home/t/.claude'],
  [cdx007, 'codex', '/home/t/.codex'],
  [opc007, 'opencode', '/home/t/.config/opencode'],
  [gem010, 'gemini-cli', '/home/t/.gemini'],
  [qc010, 'qwen-code', '/home/t/.qwen'],
  [ghc008, 'copilot-cli', '/home/t/.copilot'],
  [dev007, 'devin', '/home/t/.config/devin'],
];

const CHECKS = MODULES.map(([c, a, d]) => [c.id, c, a, d] as const);

function ctxWith(agent: AgentType, installDir: string, content: string): ScanContext {
  const fs = {
    access: vi.fn(async () => true),
    readFile: vi.fn(async () => content),
    readdir: vi.fn(async () => []),
    readdirEntries: vi.fn(async () => []),
    homedir: () => '/home/t',
    platform: 'linux',
  } as unknown as FSProvider;
  return { installation: { agent, installDir, configFiles: [] }, configs: [], platform: 'linux', fs };
}

describe('memory-file secret checks', () => {
  it.each(CHECKS)('%s flags an sk-proj- key as critical', async (_id, check, agent, dir) => {
    const r = await check.run(ctxWith(agent, dir, `Use ${PROJ} for the API`));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
  });

  it.each(CHECKS)('%s reports a high-entropy string alone as a warning', async (_id, check, agent, dir) => {
    const r = await check.run(ctxWith(agent, dir, 'token: "MuK5z1eQATYLId92VoWwSfcrv7qmRBnh6yOHkxsjtP3abFCNg4lXGi0E"'));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('warning');
  });

  it.each(CHECKS)('%s passes clean prose', async (_id, check, agent, dir) => {
    const r = await check.run(ctxWith(agent, dir, '# Notes\n\nRun the tests before committing.\n'));
    expect(r.passed).toBe(true);
  });
});
