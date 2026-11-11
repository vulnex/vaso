import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { runSkillAudit } from './skill-audit.js';
import type { ScanResult } from '../core/types.js';

// Mock fs/promises.stat
const mockStat = vi.fn();
const mockReaddir = vi.fn().mockResolvedValue([]);
vi.mock('node:fs/promises', () => ({
  stat: (...args: unknown[]) => mockStat(...args),
  readdir: (...args: unknown[]) => mockReaddir(...args),
  writeFile: vi.fn(),
}));

// Mock getSkillFiles
const mockGetSkillFiles = vi.fn();
vi.mock('../core/utils.js', () => ({
  getSkillFiles: (...args: unknown[]) => mockGetSkillFiles(...args),
}));

// Mock the directory walk (symlinks / documentation files)
const mockReaddirEntries = vi.fn();
vi.mock('../core/local-fs-provider.js', () => ({
  LocalFSProvider: vi.fn().mockImplementation(function () {
    return { readdirEntries: (...args: unknown[]) => mockReaddirEntries(...args) };
  }),
}));

// Mock ScanEngine
const mockScanSkill = vi.fn();
vi.mock('../core/engine.js', () => ({
  ScanEngine: vi.fn().mockImplementation(function () {
    return { scanSkill: mockScanSkill };
  }),
}));

// Mock getReporter
const mockRender = vi.fn().mockReturnValue('rendered output');
vi.mock('../reporting/index.js', () => ({
  getReporter: vi.fn().mockReturnValue({
    render: (...args: unknown[]) => mockRender(...args),
  }),
}));

const sampleScanResult: ScanResult = {
  timestamp: '2026-01-01T00:00:00.000Z',
  agents: [
    {
      agent: 'skill-audit',
      installation: { agent: 'skill-audit', installDir: '/tmp/skill', configFiles: [] },
      results: [
        { id: 'SKL-001', name: 'Data Exfiltration', category: 'skills', severity: 'warning', passed: true, message: 'No data exfil' },
      ],
      score: 100,
      grade: 'A',
    },
  ],
  totalScore: 100,
  totalGrade: 'A',
  fleetAverage: 100,
  summary: { critical: 0, warning: 0, info: 0, passed: 1, total: 1 },
};

const criticalScanResult: ScanResult = {
  ...sampleScanResult,
  agents: [{
    ...sampleScanResult.agents[0],
    results: [
      { id: 'SKL-002', name: 'Obfuscated Code', category: 'skills', severity: 'critical', passed: false, message: 'Obfuscated code detected' },
    ],
  }],
};

let consoleLogs: string[];
let consoleErrorLogs: string[];
const originalLog = console.log;
const originalError = console.error;

beforeEach(() => {
  consoleLogs = [];
  consoleErrorLogs = [];
  console.log = (...args: unknown[]) => {
    consoleLogs.push(args.map(String).join(' '));
  };
  console.error = (...args: unknown[]) => {
    consoleErrorLogs.push(args.map(String).join(' '));
  };
  process.exitCode = undefined;
  vi.clearAllMocks();
  mockRender.mockReturnValue('rendered output');
});

afterEach(() => {
  console.log = originalLog;
  console.error = originalError;
  process.exitCode = undefined;
});

describe('runSkillAudit', () => {
  it('errors when path does not exist', async () => {
    mockStat.mockRejectedValue(new Error('ENOENT'));

    await runSkillAudit('/nonexistent', { format: 'terminal' });

    expect(process.exitCode).toBe(2);
    expect(consoleErrorLogs.join('\n')).toContain('Path does not exist');
    expect(mockScanSkill).not.toHaveBeenCalled();
  });

  it('errors when path is not a directory', async () => {
    mockStat.mockResolvedValue({ isDirectory: () => false });

    await runSkillAudit('/some/file.txt', { format: 'terminal' });

    expect(process.exitCode).toBe(2);
    expect(consoleErrorLogs.join('\n')).toContain('Path is not a directory');
    expect(mockScanSkill).not.toHaveBeenCalled();
  });

  it('dt21 g8-F20: errors (exit 2) when the directory can\'t be listed, instead of calling it empty', async () => {
    mockStat.mockResolvedValue({ isDirectory: () => true });
    mockReaddir.mockRejectedValueOnce(Object.assign(new Error('EACCES: permission denied'), { code: 'EACCES' }));

    await runSkillAudit('/locked/skill', { format: 'terminal' });

    expect(process.exitCode).toBe(2);
    expect(consoleErrorLogs.join('\n')).toContain('Cannot read directory: /locked/skill (EACCES)');
    expect(consoleErrorLogs.join('\n')).not.toContain('is empty');
    expect(mockScanSkill).not.toHaveBeenCalled();
  });

  it('shows message when no code files found', async () => {
    mockStat.mockResolvedValue({ isDirectory: () => true });
    mockGetSkillFiles.mockResolvedValue([]);

    mockReaddirEntries.mockResolvedValue([]);

    await runSkillAudit('/empty/skill', { format: 'terminal' });

    expect(consoleErrorLogs.join('\n')).toContain('is empty. Nothing to audit');
    expect(mockScanSkill).not.toHaveBeenCalled();
    expect(process.exitCode).toBeUndefined();
  });

  it('audits an instructions-only skill (SKILL.md, no code) for prompt injection', async () => {
    mockStat.mockResolvedValue({ isDirectory: () => true });
    mockGetSkillFiles.mockResolvedValue([]);
    mockReaddirEntries.mockResolvedValue([{ name: 'SKILL.md', isFile: true, isDirectory: false }]);
    mockScanSkill.mockResolvedValue(sampleScanResult);

    await runSkillAudit('/tmp/md-skill', { format: 'json' });

    expect(mockScanSkill).toHaveBeenCalledWith(expect.stringContaining('md-skill'), [], expect.anything());
    expect(consoleErrorLogs.join('\n')).toContain('(no code files)');
  });

  it('audits a directory holding only metadata and config (IOC checks read them)', async () => {
    mockStat.mockResolvedValue({ isDirectory: () => true });
    mockGetSkillFiles.mockResolvedValue([]);
    mockReaddirEntries.mockResolvedValue([
      { name: 'package.json', isFile: true, isDirectory: false },
      { name: 'config.json', isFile: true, isDirectory: false },
    ]);
    mockScanSkill.mockResolvedValue(sampleScanResult);

    await runSkillAudit('/tmp/meta-skill', { format: 'json' });

    expect(mockScanSkill).toHaveBeenCalled();
  });

  it('fails on warnings with --fail-on warning; rejects a bad level', async () => {
    mockStat.mockResolvedValue({ isDirectory: () => true });
    mockGetSkillFiles.mockResolvedValue(['/tmp/skill/index.js']);
    mockScanSkill.mockResolvedValue({
      ...sampleScanResult,
      agents: [{ ...sampleScanResult.agents[0], results: [{ id: 'SKL-007', name: 'x', category: 'skills', severity: 'warning', passed: false, message: 'm' }] }],
    });
    await runSkillAudit('/tmp/skill', { format: 'json' });
    expect(process.exitCode).toBeUndefined();
    await runSkillAudit('/tmp/skill', { format: 'json', failOn: 'warning' });
    expect(process.exitCode).toBe(1);
    process.exitCode = undefined;
    await runSkillAudit('/tmp/skill', { format: 'json', failOn: 'bogus' });
    expect(process.exitCode).toBe(2);
    process.exitCode = undefined;
  });

  it('runs scan and renders output on happy path', async () => {
    mockStat.mockResolvedValue({ isDirectory: () => true });
    mockGetSkillFiles.mockResolvedValue(['/tmp/skill/index.js', '/tmp/skill/helper.ts']);
    mockScanSkill.mockResolvedValue(sampleScanResult);

    await runSkillAudit('/tmp/skill', { format: 'json' });

    expect(mockScanSkill).toHaveBeenCalledWith(
      expect.stringContaining('skill'),
      ['/tmp/skill/index.js', '/tmp/skill/helper.ts'],
      expect.objectContaining({ format: 'json' }),
    );
    expect(consoleLogs.join('\n')).toContain('rendered output');
    expect(process.exitCode).toBeUndefined();
  });

  it('sets exitCode=1 on critical findings', async () => {
    mockStat.mockResolvedValue({ isDirectory: () => true });
    mockGetSkillFiles.mockResolvedValue(['/tmp/skill/evil.js']);
    mockScanSkill.mockResolvedValue(criticalScanResult);

    await runSkillAudit('/tmp/skill', { format: 'terminal' });

    expect(process.exitCode).toBe(1);
  });

  it('writes to file when --output is specified', async () => {
    mockStat.mockResolvedValue({ isDirectory: () => true });
    mockGetSkillFiles.mockResolvedValue(['/tmp/skill/index.js']);
    mockScanSkill.mockResolvedValue(sampleScanResult);

    const { writeFile: mockWriteFile } = await import('node:fs/promises');

    await runSkillAudit('/tmp/skill', { format: 'json', output: '/tmp/report.json' });

    expect(mockWriteFile).toHaveBeenCalledWith('/tmp/report.json', 'rendered output', 'utf-8');
    expect(consoleErrorLogs.join('\n')).toContain('Report written to');
  });

  it('handles scan engine errors gracefully', async () => {
    mockStat.mockResolvedValue({ isDirectory: () => true });
    mockGetSkillFiles.mockResolvedValue(['/tmp/skill/index.js']);
    mockScanSkill.mockRejectedValue(new Error('Engine boom'));

    await runSkillAudit('/tmp/skill', { format: 'terminal' });

    expect(process.exitCode).toBe(2);
    expect(consoleErrorLogs.join('\n')).toContain('Skill audit failed');
  });
});
