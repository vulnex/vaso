import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, readFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { emitBundle } from './bundle.js';
import type { ScanResult, AgentScanResult, CheckResult } from '../core/types.js';
import type { AgentAdapter } from '../adapters/adapter.js';
import { parse as parseToml } from 'smol-toml';

function check(overrides: Partial<CheckResult>): CheckResult {
  return {
    id: 'X-001', name: 'X', category: 'config', severity: 'warning',
    passed: false, message: 'fail', ...overrides,
  };
}

function agentScan(overrides: Partial<AgentScanResult> = {}): AgentScanResult {
  return {
    agent: 'openclaw',
    installation: {
      agent: 'openclaw',
      installDir: '/home/u/.openclaw',
      configFiles: [],
    },
    results: [],
    score: 90,
    grade: 'A',
    ...overrides,
  };
}

function scanResult(agents: AgentScanResult[]): ScanResult {
  return {
    timestamp: '2026-04-27T12:00:00Z',
    agents,
    totalScore: 90,
    totalGrade: 'A',
    summary: { critical: 0, warning: 0, info: 0, passed: 0, total: 0 },
  };
}

const noopAdapters = new Map<string, AgentAdapter>();

describe('emitBundle', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'vaso-vis-'));
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('writes topology + per-agent attack-tree + per-agent privilege-gradient + readme', async () => {
    const result = scanResult([
      agentScan({
        results: [check({ id: 'CFG-001', severity: 'critical' })],
      }),
    ]);
    const bundle = await emitBundle(result, {
      outputDir: dir,
      format: 'toml',
      diagrams: ['attack-tree', 'privilege-gradient', 'component'],
      adapters: noopAdapters,
    });
    expect(bundle.files.map(f => f.diagram).sort()).toEqual([
      'attack-tree', 'component', 'privilege-gradient', 'readme',
    ]);
    const written = await readdir(dir);
    expect(written.sort()).toEqual([
      'README.md',
      'openclaw-attack-tree.toml',
      'openclaw-privilege-gradient.toml',
      'topology.toml',
    ]);
  });

  it('respects --diagrams filter', async () => {
    const result = scanResult([agentScan({ results: [check({})] })]);
    await emitBundle(result, {
      outputDir: dir, format: 'json',
      diagrams: ['attack-tree'],
      adapters: noopAdapters,
    });
    const written = await readdir(dir);
    expect(written.sort()).toEqual(['README.md', 'openclaw-attack-tree.json']);
  });

  it('produces parseable TOML for the attack tree', async () => {
    const result = scanResult([agentScan({ results: [check({ id: 'CFG-001' })] })]);
    await emitBundle(result, {
      outputDir: dir, format: 'toml', diagrams: ['attack-tree'], adapters: noopAdapters,
    });
    const toml = await readFile(join(dir, 'openclaw-attack-tree.toml'), 'utf-8');
    const parsed = parseToml(toml) as Record<string, unknown>;
    expect(parsed.tree).toBeDefined();
    expect(parsed.nodes).toBeDefined();
    expect(parsed.edges).toBeDefined();
  });

  it('produces parseable JSON for the privilege gradient with no failures', async () => {
    const result = scanResult([agentScan({ results: [check({ passed: true })] })]);
    await emitBundle(result, {
      outputDir: dir, format: 'json', diagrams: ['privilege-gradient'], adapters: noopAdapters,
    });
    const json = JSON.parse(await readFile(join(dir, 'openclaw-privilege-gradient.json'), 'utf-8'));
    expect(json.gradient.type).toBe('Privilege Gradient Graph');
    expect(json.zones.length).toBeGreaterThan(0);
    expect(json.influences.every((i: { triggered?: boolean }) => i.triggered === undefined)).toBe(true);
  });

  it('disambiguates per-installation slugs when multiple installations of the same agent exist', async () => {
    const result = scanResult([
      agentScan({ installation: { agent: 'openclaw', agentName: 'work', installDir: '/a', configFiles: [] } }),
      agentScan({ installation: { agent: 'openclaw', agentName: 'home', installDir: '/b', configFiles: [] } }),
    ]);
    await emitBundle(result, {
      outputDir: dir, format: 'json', diagrams: ['attack-tree'], adapters: noopAdapters,
    });
    const written = await readdir(dir);
    expect(written).toContain('openclaw-work-attack-tree.json');
    expect(written).toContain('openclaw-home-attack-tree.json');
  });

  it('writes a README that lists all bundle files and the usecvis commands', async () => {
    const result = scanResult([agentScan({ results: [check({})] })]);
    await emitBundle(result, {
      outputDir: dir, format: 'toml',
      diagrams: ['attack-tree', 'privilege-gradient', 'component'],
      adapters: noopAdapters,
    });
    const readme = await readFile(join(dir, 'README.md'), 'utf-8');
    expect(readme).toContain('VASO Visualization Bundle');
    expect(readme).toMatch(/usecvis -m 0 -i .+attack-tree/);
    expect(readme).toMatch(/usecvis -m 6 -i .+privilege-gradient/);
    expect(readme).toMatch(/usecvis -m 7 -i topology/);
    expect(readme).toContain('Note on CVSS scores');
  });
});
