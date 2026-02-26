import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('node:fs/promises', () => ({
  readdir: vi.fn(),
  copyFile: vi.fn(),
}));

vi.mock('node:os', () => ({
  homedir: vi.fn(() => '/home/testuser'),
}));

vi.mock('../core/utils.js', () => ({
  pathExists: vi.fn(),
}));

import { readdir, copyFile } from 'node:fs/promises';
import { pathExists } from '../core/utils.js';
import { rollback } from './rollback.js';

const mockReaddir = vi.mocked(readdir);
const mockCopyFile = vi.mocked(copyFile);
const mockPathExists = vi.mocked(pathExists);

describe('rollback', () => {
  let consoleLogs: string[];

  beforeEach(() => {
    vi.resetAllMocks();
    consoleLogs = [];
    vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      consoleLogs.push(args.map(String).join(' '));
    });
  });

  it('reports no backups when directory missing', async () => {
    mockPathExists.mockResolvedValue(false);
    await rollback();
    expect(consoleLogs.some(l => l.includes('No backups found'))).toBe(true);
  });

  it('reports empty backups directory', async () => {
    mockPathExists.mockResolvedValue(true);
    mockReaddir.mockResolvedValueOnce([] as any);
    await rollback();
    expect(consoleLogs.some(l => l.includes('No backup directories'))).toBe(true);
  });

  it('uses most recent backup when no timestamp given', async () => {
    mockPathExists.mockResolvedValue(true);
    mockReaddir
      // First readdir: list backup directories
      .mockResolvedValueOnce([
        { name: '2026-01-01T00-00-00', isDirectory: () => true, isFile: () => false },
        { name: '2026-02-01T00-00-00', isDirectory: () => true, isFile: () => false },
      ] as any)
      // Second readdir: files inside the backup dir (recursive)
      .mockResolvedValueOnce([
        { name: 'config.yaml', isFile: () => true, isDirectory: () => false, parentPath: '/home/testuser/.vaso/backups/2026-02-01T00-00-00/etc' },
      ] as any);
    mockCopyFile.mockResolvedValue(undefined);

    await rollback();
    expect(consoleLogs.some(l => l.includes('2026-02-01T00-00-00'))).toBe(true);
  });

  it('finds backup matching timestamp', async () => {
    mockPathExists.mockResolvedValue(true);
    mockReaddir
      .mockResolvedValueOnce([
        { name: '2026-01-01T00-00-00', isDirectory: () => true, isFile: () => false },
        { name: '2026-02-15T12-30-00', isDirectory: () => true, isFile: () => false },
      ] as any)
      .mockResolvedValueOnce([] as any);

    await rollback('2026-02-15');
    expect(consoleLogs.some(l => l.includes('2026-02-15T12-30-00'))).toBe(true);
  });

  it('shows error and available backups when no match', async () => {
    mockPathExists.mockResolvedValue(true);
    mockReaddir.mockResolvedValueOnce([
      { name: '2026-01-01T00-00-00', isDirectory: () => true, isFile: () => false },
    ] as any);

    await rollback('2099-12-31');
    expect(consoleLogs.some(l => l.includes('No backup matching'))).toBe(true);
    expect(consoleLogs.some(l => l.includes('2026-01-01T00-00-00'))).toBe(true);
  });

  it('restores files and reports count', async () => {
    mockPathExists.mockResolvedValue(true);
    mockReaddir
      .mockResolvedValueOnce([
        { name: '2026-02-01T00-00-00', isDirectory: () => true, isFile: () => false },
      ] as any)
      .mockResolvedValueOnce([
        { name: 'config.yaml', isFile: () => true, isDirectory: () => false, parentPath: '/home/testuser/.vaso/backups/2026-02-01T00-00-00/etc' },
        { name: 'settings.json', isFile: () => true, isDirectory: () => false, parentPath: '/home/testuser/.vaso/backups/2026-02-01T00-00-00/etc' },
      ] as any);
    mockCopyFile.mockResolvedValue(undefined);

    await rollback();
    expect(consoleLogs.some(l => l.includes('2 file(s) restored'))).toBe(true);
  });

  it('handles copy failure gracefully', async () => {
    mockPathExists.mockResolvedValue(true);
    mockReaddir
      .mockResolvedValueOnce([
        { name: '2026-02-01T00-00-00', isDirectory: () => true, isFile: () => false },
      ] as any)
      .mockResolvedValueOnce([
        { name: 'config.yaml', isFile: () => true, isDirectory: () => false, parentPath: '/home/testuser/.vaso/backups/2026-02-01T00-00-00/etc' },
      ] as any);
    mockCopyFile.mockRejectedValue(new Error('Permission denied'));

    await rollback();
    expect(consoleLogs.some(l => l.includes('Failed to restore'))).toBe(true);
    expect(consoleLogs.some(l => l.includes('0 file(s) restored'))).toBe(true);
  });
});
