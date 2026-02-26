import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../ioc/updater.js', () => ({
  fetchAndUpdateFeed: vi.fn(),
}));

vi.mock('../ioc/database.js', () => ({
  reloadIOCDatabase: vi.fn(),
  getIOCDatabase: vi.fn(),
  initIOCDatabase: vi.fn(),
}));

vi.mock('../advisory/updater.js', () => ({
  fetchAndUpdateAdvisoryFeed: vi.fn(),
}));

vi.mock('../advisory/database.js', () => ({
  reloadAdvisoryDatabase: vi.fn(),
  getAdvisoryDatabase: vi.fn(),
  initAdvisoryDatabase: vi.fn(),
}));

import { fetchAndUpdateFeed } from '../ioc/updater.js';
import { reloadIOCDatabase, getIOCDatabase, initIOCDatabase } from '../ioc/database.js';
import { fetchAndUpdateAdvisoryFeed } from '../advisory/updater.js';
import { reloadAdvisoryDatabase, getAdvisoryDatabase, initAdvisoryDatabase } from '../advisory/database.js';
import { runUpdate } from './update.js';

const mockFetchIOC = vi.mocked(fetchAndUpdateFeed);
const mockReloadIOC = vi.mocked(reloadIOCDatabase);
const mockGetIOC = vi.mocked(getIOCDatabase);
const mockInitIOC = vi.mocked(initIOCDatabase);
const mockFetchAdvisory = vi.mocked(fetchAndUpdateAdvisoryFeed);
const mockReloadAdvisory = vi.mocked(reloadAdvisoryDatabase);
const mockGetAdvisory = vi.mocked(getAdvisoryDatabase);
const mockInitAdvisory = vi.mocked(initAdvisoryDatabase);

function makeIOCDb() {
  return {
    c2Ips: ['1.2.3.4'],
    maliciousDomains: ['evil.com'],
    fileHashes: ['abc123'],
    maliciousPublishers: ['@bad'],
    maliciousSkillPatterns: ['pattern1'],
    trustedSkillNames: ['safe-skill'],
    trustedMCPPackages: ['@mcp/safe'],
    binaryPatterns: ['bin1'],
  };
}

describe('runUpdate', () => {
  let consoleLogs: string[];

  beforeEach(() => {
    vi.resetAllMocks();
    consoleLogs = [];
    vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      consoleLogs.push(args.map(String).join(' '));
    });
    mockInitIOC.mockResolvedValue(undefined);
    mockInitAdvisory.mockResolvedValue(undefined);
  });

  it('shows indicator counts on successful IOC update', async () => {
    mockFetchIOC.mockResolvedValue({
      success: true,
      message: 'Updated successfully',
      newIndicators: {
        c2Ips: 5,
        maliciousDomains: 3,
        fileHashes: 2,
        maliciousPublishers: 1,
        maliciousSkillPatterns: 0,
        trustedSkillNames: 0,
        trustedMCPPackages: 0,
        binaryPatterns: 0,
      },
    });
    mockGetIOC.mockReturnValue(makeIOCDb() as any);
    mockFetchAdvisory.mockResolvedValue({ success: true, message: 'Advisory updated' });
    mockGetAdvisory.mockReturnValue({ advisories: [{ id: 'ADV-001' }] } as any);

    await runUpdate();
    expect(consoleLogs.some(l => l.includes('Updated successfully'))).toBe(true);
    expect(consoleLogs.some(l => l.includes('C2 IPs: 5'))).toBe(true);
  });

  it('shows fallback message on IOC failure', async () => {
    mockFetchIOC.mockResolvedValue({
      success: false,
      message: 'Network error',
    });

    await runUpdate();
    expect(consoleLogs.some(l => l.includes('Network error'))).toBe(true);
    expect(consoleLogs.some(l => l.includes('Falling back to bundled IOC data'))).toBe(true);
  });

  it('reloads IOC database after successful update', async () => {
    mockFetchIOC.mockResolvedValue({ success: true, message: 'ok' });
    mockGetIOC.mockReturnValue(makeIOCDb() as any);
    mockFetchAdvisory.mockResolvedValue({ success: true, message: 'ok' });
    mockGetAdvisory.mockReturnValue({ advisories: [] } as any);

    await runUpdate();
    expect(mockReloadIOC).toHaveBeenCalled();
    expect(mockInitIOC).toHaveBeenCalled();
  });

  it('shows advisory update success', async () => {
    mockFetchIOC.mockResolvedValue({ success: true, message: 'ok' });
    mockGetIOC.mockReturnValue(makeIOCDb() as any);
    mockFetchAdvisory.mockResolvedValue({
      success: true,
      message: 'Advisory feed updated',
      newAdvisories: 42,
    });
    mockGetAdvisory.mockReturnValue({ advisories: new Array(42) } as any);

    await runUpdate();
    expect(consoleLogs.some(l => l.includes('Advisory feed updated'))).toBe(true);
    expect(consoleLogs.some(l => l.includes('42'))).toBe(true);
  });

  it('shows fallback message on advisory failure', async () => {
    mockFetchIOC.mockResolvedValue({ success: true, message: 'ok' });
    mockGetIOC.mockReturnValue(makeIOCDb() as any);
    mockFetchAdvisory.mockResolvedValue({
      success: false,
      message: 'Advisory fetch failed',
    });
    mockGetAdvisory.mockReturnValue({ advisories: [] } as any);

    await runUpdate();
    expect(consoleLogs.some(l => l.includes('Advisory fetch failed'))).toBe(true);
    expect(consoleLogs.some(l => l.includes('Falling back to bundled advisory data'))).toBe(true);
  });

  it('passes URL and force options to IOC updater', async () => {
    mockFetchIOC.mockResolvedValue({ success: true, message: 'ok' });
    mockGetIOC.mockReturnValue(makeIOCDb() as any);
    mockFetchAdvisory.mockResolvedValue({ success: true, message: 'ok' });
    mockGetAdvisory.mockReturnValue({ advisories: [] } as any);

    await runUpdate({ url: 'https://custom.feed/ioc', force: false });
    expect(mockFetchIOC).toHaveBeenCalledWith(
      expect.objectContaining({ feedUrl: 'https://custom.feed/ioc', force: false }),
    );
  });

  it('reports merged IOC database totals', async () => {
    mockFetchIOC.mockResolvedValue({ success: true, message: 'ok' });
    mockGetIOC.mockReturnValue(makeIOCDb() as any);
    mockFetchAdvisory.mockResolvedValue({ success: true, message: 'ok' });
    mockGetAdvisory.mockReturnValue({ advisories: [] } as any);

    await runUpdate();
    expect(consoleLogs.some(l => l.includes('Merged IOC database totals'))).toBe(true);
    expect(consoleLogs.some(l => l.includes('C2 IPs: 1'))).toBe(true);
  });
});
