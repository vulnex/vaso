import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ParsedConfig, ScanContext } from '../core/types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { gem010 } from './gemini-cli/gem-010-memory-secrets.js';
import { qc010 } from './qwen-code/qc-010-memory-secrets.js';
import { dev007 } from './devin/dev-007-agents-md-secrets.js';
import { ws006 } from './windsurf-app/ws-006-workflow-turbo-directive.js';
import { ic002 } from './ironclaw/ic-002-no-tls.js';
import { geminiAdapter } from '../adapters/gemini.js';

const HOME = '/home/test';

function fakeFs(files: Record<string, string>, kind?: 'snapshot'): FSProvider {
  const enoent = (p: string) => Object.assign(new Error(`ENOENT ${p}`), { code: 'ENOENT' });
  return {
    platform: 'linux',
    kind,
    homedir: () => HOME,
    getEnv: () => undefined,
    access: vi.fn(async (p: string) => p in files),
    readFile: vi.fn(async (p: string) => { if (!(p in files)) throw enoent(p); return files[p]; }),
    stat: vi.fn(async (p: string) => { if (!(p in files)) throw enoent(p); return { mode: 0o100600, isFile: () => true, isDirectory: () => false }; }),
    readdirEntries: vi.fn(async () => []),
  } as unknown as FSProvider;
}

function ctx(agent: ScanContext['installation']['agent'], installDir: string, fs: FSProvider, settings: Record<string, unknown> = {}, profile?: string): ScanContext {
  const config: ParsedConfig = { raw: JSON.stringify(settings), format: 'json', filePath: join(installDir, 'settings.json'), data: settings };
  return {
    installation: { agent, installDir, configFiles: [config], ...(profile ? { profile } : {}) },
    configs: [config], platform: 'linux', fs,
  };
}

const KEY = 'sk-ant-api03-Zq8wLm3vT9kR2pN7aY4cB6dFhJ2kL5mN8pQ1rS4t';

describe('GEM-010 reads context.fileName (dt21 g6-F5)', () => {
  const GEM = `${HOME}/.gemini`;

  it('scans the configured context files (string or array)', async () => {
    const fs = fakeFs({ [`${GEM}/AGENTS.md`]: `key: ${KEY}\n`, [`${GEM}/CONTEXT.md`]: 'nothing here\n' });
    for (const fileName of [['AGENTS.md', 'CONTEXT.md'], 'AGENTS.md']) {
      const r = await gem010.run(ctx('gemini-cli', GEM, fs, { context: { fileName } }, 'project'));
      expect(r.passed).toBe(false);
      expect(r.evidence!.some(e => e.file === `${GEM}/AGENTS.md`)).toBe(true);
    }
  });

  it('loads names with directories as the CLI does: path.join(~/.gemini, name) (dt21 g6-R1)', async () => {
    const fs = fakeFs({
      [`${GEM}/sub/deep.md`]: `key: ${KEY}\n`,
      [`${HOME}/notes/n.md`]: `key: ${KEY}\n`,
      [`${GEM}/abs/x.md`]: `key: ${KEY}\n`,
    });
    const r = await gem010.run(ctx('gemini-cli', GEM, fs, { context: { fileName: ['sub/deep.md', '../notes/n.md', '/abs/x.md', '..', 'dir/'] } }, 'project'));
    expect(r.passed).toBe(false);
    // an absolute name is skipped: joined to ~/.gemini it names some other path
    expect(new Set(r.evidence!.map(e => e.file))).toEqual(new Set([`${GEM}/sub/deep.md`, `${HOME}/notes/n.md`]));
  });

  it('says why a context file was not collected on a snapshot, and names no phantom path (dt21 g6-R2c)', async () => {
    const r = await gem010.run(ctx('gemini-cli', GEM, fakeFs({}, 'snapshot'), { context: { fileName: ['sub/deep.md', '../notes/n.md', '/abs/x.md', 'CONTEXT'] } }, 'project'));
    expect(r.passed).toBe(true);
    expect(r.message).toContain(`${GEM}/sub/deep.md (not collected: not at the top of ~/.gemini)`);
    expect(r.message).toContain(`${HOME}/notes/n.md (not collected: outside ~/.gemini)`);
    expect(r.message).toContain(`${GEM}/CONTEXT (not collected: not a .md file)`);
    expect(r.message).not.toContain('abs/x.md');
  });

  it('collects every top-level ~/.gemini markdown file in the probe manifest', () => {
    expect(geminiAdapter.getProbeManifest!().globPatterns).toContain('~/.gemini/*.md');
  });

  it('says a non-.md context file was not verified on a snapshot', async () => {
    const r = await gem010.run(ctx('gemini-cli', GEM, fakeFs({}, 'snapshot'), { context: { fileName: 'CONTEXT' } }, 'project'));
    expect(r.passed).toBe(true);
    expect(r.message).toContain(`${GEM}/CONTEXT (not collected: not a .md file) not verified`);
  });
});

describe('QC-010 non-.md context file on a snapshot (dt21 g6-F6)', () => {
  const QWEN = `${HOME}/.qwen`;

  it('notes it as not verified instead of a plain clean pass', async () => {
    const r = await qc010.run(ctx('qwen-code', QWEN, fakeFs({}, 'snapshot'), { context: { fileName: ['CONTEXT', 'notes.rst'] } }));
    expect(r.passed).toBe(true);
    expect(r.message).toContain(`${QWEN}/CONTEXT (not collected: not a .md file)`);
    expect(r.message).toContain(`${QWEN}/notes.rst (not collected: not a .md file)`);
  });

  it('adds no note on a local scan', async () => {
    const r = await qc010.run(ctx('qwen-code', QWEN, fakeFs({}), { context: { fileName: ['CONTEXT'] } }));
    expect(r.message).toBe('No secrets detected in Qwen memory files');
  });
});

describe('DEV-007 and WS-006 on real files', () => {
  let home: string;
  let cwd: string;
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'vaso-dt21-'));
    cwd = process.cwd();
  });
  afterEach(() => {
    process.chdir(cwd);
    rmSync(home, { recursive: true, force: true });
  });

  function localFs(): FSProvider {
    const fs = new LocalFSProvider();
    return Object.assign(Object.create(Object.getPrototypeOf(fs)), fs, { homedir: () => home }) as FSProvider;
  }

  it('DEV-007 skips a symlink to a directory named *.md (dt21 g7-L2) but reads a linked file', async () => {
    const rules = join(home, '.devin', 'rules');
    mkdirSync(rules, { recursive: true });
    mkdirSync(join(home, 'somedir'));
    symlinkSync('../../somedir', join(rules, 'linkdir.md'));
    writeFileSync(join(home, 'real.md'), `token: ${KEY}\n`);
    symlinkSync('../../real.md', join(rules, 'linked.md'));
    const installDir = join(home, '.config', 'devin');
    mkdirSync(installDir, { recursive: true });
    const r = await dev007.run({ installation: { agent: 'devin', installDir, configFiles: [] }, configs: [], platform: process.platform as NodeJS.Platform, fs: localFs() });
    expect(r.errored).toBeFalsy();
    expect(r.passed).toBe(false);
    expect(r.evidence!.every(e => e.file.endsWith('linked.md'))).toBe(true);
  });

  it('WS-006 matches the directive line only, not `// turbocharged` prose (dt21 g7-L1)', async () => {
    const wf = join(home, '.codeium', 'windsurf', 'global_workflows');
    mkdirSync(wf, { recursive: true });
    writeFileSync(join(wf, 'build.md'), [
      '# Build',
      '1. Run the build // turbocharged build',
      '// turbo',
      '2. npm test',
      '  - // turbo-all\r',
      'Use `// turbo` above a step to auto-run it.',
    ].join('\n'));
    process.chdir(home);
    const r = await ws006.run({ installation: { agent: 'windsurf', installDir: join(home, '.codeium', 'windsurf'), configFiles: [] }, configs: [], platform: process.platform as NodeJS.Platform, fs: localFs() });
    expect(r.evidence!.map(e => e.line)).toEqual([3, 5]);
    expect(r.evidence![1].detail).toContain('turbo-all');
  });
});

describe('IC-002 cites each [llm.*] table\'s own line (dt21 g5-F8)', () => {
  it('points the second base_url at its own line', async () => {
    const raw = [
      '[llm.default]', 'provider = "openai"', 'base_url = "http://10.0.0.5:11434/v1"', '',
      '[llm."backup"]', 'provider = "ollama"', 'base_url = "http://10.0.0.6:11434"', '',
    ].join('\n');
    const data = { llm: { default: { provider: 'openai', base_url: 'http://10.0.0.5:11434/v1' }, backup: { provider: 'ollama', base_url: 'http://10.0.0.6:11434' } } };
    const config: ParsedConfig = { raw, format: 'toml', filePath: `${HOME}/.ironclaw/reborn/config.toml`, data };
    const r = await ic002.run({
      installation: { agent: 'ironclaw', installDir: `${HOME}/.ironclaw/reborn`, configFiles: [config], profile: 'reborn' },
      configs: [config], platform: 'linux', fs: fakeFs({}),
    });
    const lines = Object.fromEntries(r.evidence!.map(e => [e.snippet!.split(' = ')[0], e.line]));
    expect(lines).toEqual({ '[llm.default].base_url': 3, '[llm.backup].base_url': 7 });
  });
});
