import { describe, it, expect } from 'vitest';
import { ScanEngine } from './engine.js';
import { CheckRegistry } from './check-registry.js';
import { AdapterRegistry } from '../adapters/registry.js';
import type { CheckModule, ScanContext, CheckResult, AgentInstallation } from './types.js';
import type { AgentAdapter } from '../adapters/adapter.js';

const mockInstallation: AgentInstallation = {
  agent: 'openclaw',
  installDir: '/tmp/test-openclaw',
  configFiles: [],
};

const mockAdapter: AgentAdapter = {
  agent: 'openclaw',
  displayName: 'OpenClaw',
  async detect() { return mockInstallation; },
  getConfigPaths() { return []; },
  getSkillsDir() { return undefined; },
  getGatewayInfo() { return undefined; },
};

function mockCheck(id: string, passed: boolean, severity: 'critical' | 'warning' | 'info' = 'warning'): CheckModule {
  return {
    id,
    name: `Check ${id}`,
    category: 'config',
    severity,
    description: `Mock check ${id}`,
    async run(_ctx: ScanContext): Promise<CheckResult> {
      return {
        id,
        name: `Check ${id}`,
        category: 'config',
        severity,
        passed,
        message: passed ? 'OK' : 'Failed',
      };
    },
  };
}

describe('ScanEngine', () => {
  it('runs end-to-end with mock adapter and checks', async () => {
    const adapters = new AdapterRegistry();
    adapters.register(mockAdapter);

    const checks = new CheckRegistry();
    checks.register(mockCheck('CFG-001', true));
    checks.register(mockCheck('CFG-002', false, 'critical'));
    checks.register(mockCheck('CFG-003', false, 'warning'));

    const engine = new ScanEngine(adapters, checks);
    const result = await engine.scan({});

    expect(result.agents).toHaveLength(1);
    expect(result.agents[0].agent).toBe('openclaw');
    expect(result.agents[0].results).toHaveLength(3);
    expect(result.agents[0].score).toBe(83); // 100 - 12 - 5
    expect(result.agents[0].grade).toBe('B');
    expect(result.summary.critical).toBe(1);
    expect(result.summary.warning).toBe(1);
    expect(result.summary.passed).toBe(1);
  });

  it('returns empty result when no agents detected', async () => {
    const adapters = new AdapterRegistry();
    const checks = new CheckRegistry();

    const engine = new ScanEngine(adapters, checks);
    const result = await engine.scan({});

    expect(result.agents).toHaveLength(0);
    expect(result.totalScore).toBe(100);
    expect(result.totalGrade).toBe('A');
  });

  it('filters by agent name', async () => {
    const adapters = new AdapterRegistry();
    adapters.register(mockAdapter);

    const checks = new CheckRegistry();
    checks.register(mockCheck('CFG-001', true));

    const engine = new ScanEngine(adapters, checks);

    // Filter for non-existent agent
    const result = await engine.scan({ agentFilter: 'nanoclaw' });
    expect(result.agents).toHaveLength(0);

    // Filter for existing agent
    const result2 = await engine.scan({ agentFilter: 'openclaw' });
    expect(result2.agents).toHaveLength(1);
  });

  it('handles check failures gracefully', async () => {
    const adapters = new AdapterRegistry();
    adapters.register(mockAdapter);

    const checks = new CheckRegistry();
    checks.register({
      id: 'FAIL-001',
      name: 'Failing Check',
      category: 'config',
      severity: 'critical',
      description: 'Always fails',
      async run() { throw new Error('boom'); },
    });
    checks.register(mockCheck('CFG-001', true));

    const engine = new ScanEngine(adapters, checks);
    const result = await engine.scan({});

    // Failing check is excluded, passing check remains
    expect(result.agents[0].results).toHaveLength(1);
    expect(result.agents[0].results[0].passed).toBe(true);
  });
});
