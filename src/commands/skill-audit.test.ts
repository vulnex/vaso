import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { runSkillAudit } from './skill-audit.js';
import type { ScanResult } from '../core/types.js';

// Mock fs/promises.stat
const mockStat = vi.fn();
vi.mock('node:fs/promises', () => ({
  stat: (...args: unknown[]) => mockStat(...args),
  writeFile: vi.fn(),
}));

// Mock getSkillFiles
const mockGetSkillFiles = vi.fn();
vi.mock('../core/utils.js', () => ({
  getSkillFiles: (...args: unknown[]) => mockGetSkillFiles(...args),
}));

// Mock ScanEngine
const mockScanSkill = vi.fn();
vi.mock('../core/engine.js', () => ({
  ScanEngine: vi.fn().mockImplementation(() => ({
    scanSkill: mockScanSkill,
  })),
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

    expect(process.exitCode).toBe(1);
    expect(consoleErrorLogs.join('\n')).toContain('Path does not exist');
    expect(mockScanSkill).not.toHaveBeenCalled();
  });

  it('errors when path is not a directory', async () => {
    mockStat.mockResolvedValue({ isDirectory: () => false });

    await runSkillAudit('/some/file.txt', { format: 'terminal' });

    expect(process.exitCode).toBe(1);
    expect(consoleErrorLogs.join('\n')).toContain('Path is not a directory');
    expect(mockScanSkill).not.toHaveBeenCalled();
  });

  it('shows message when no code files found', async () => {
    mockStat.mockResolvedValue({ isDirectory: () => true });
    mockGetSkillFiles.mockResolvedValue([]);

    await runSkillAudit('/empty/skill', { format: 'terminal' });

    expect(consoleLogs.join('\n')).toContain('No code files found');
    expect(mockScanSkill).not.toHaveBeenCalled();
    expect(process.exitCode).toBeUndefined();
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
    expect(consoleLogs.join('\n')).toContain('Report written to');
  });

  it('handles scan engine errors gracefully', async () => {
    mockStat.mockResolvedValue({ isDirectory: () => true });
    mockGetSkillFiles.mockResolvedValue(['/tmp/skill/index.js']);
    mockScanSkill.mockRejectedValue(new Error('Engine boom'));

    await runSkillAudit('/tmp/skill', { format: 'terminal' });

    expect(process.exitCode).toBe(1);
    expect(consoleErrorLogs.join('\n')).toContain('Skill audit failed');
  });
});
