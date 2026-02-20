import { describe, it, expect } from 'vitest';
import { CheckRegistry } from './check-registry.js';
import type { CheckModule, ScanContext, CheckResult } from './types.js';

function makeMockCheck(overrides: Partial<CheckModule> = {}): CheckModule {
  return {
    id: 'MOCK-001',
    name: 'Mock Check',
    category: 'config',
    severity: 'warning',
    description: 'A mock check',
    async run(_ctx: ScanContext): Promise<CheckResult> {
      return {
        id: 'MOCK-001',
        name: 'Mock Check',
        category: 'config',
        severity: 'warning',
        passed: true,
        message: 'OK',
      };
    },
    ...overrides,
  };
}

describe('CheckRegistry', () => {
  it('registers and retrieves checks', () => {
    const registry = new CheckRegistry();
    const check = makeMockCheck();
    registry.register(check);
    expect(registry.getAll()).toHaveLength(1);
    expect(registry.getAll()[0].id).toBe('MOCK-001');
  });

  it('prevents duplicate registration', () => {
    const registry = new CheckRegistry();
    registry.register(makeMockCheck());
    expect(() => registry.register(makeMockCheck())).toThrow('already registered');
  });

  it('filters by category', () => {
    const registry = new CheckRegistry();
    registry.register(makeMockCheck({ id: 'CFG-001', category: 'config' }));
    registry.register(makeMockCheck({ id: 'SKL-001', category: 'skills' }));

    expect(registry.getByCategory('config')).toHaveLength(1);
    expect(registry.getByCategory('skills')).toHaveLength(1);
    expect(registry.getByCategory('ioc')).toHaveLength(0);
  });

  it('filters by agent', () => {
    const registry = new CheckRegistry();
    registry.register(makeMockCheck({ id: 'A', supportedAgents: ['openclaw'] }));
    registry.register(makeMockCheck({ id: 'B', supportedAgents: ['nanoclaw'] }));
    registry.register(makeMockCheck({ id: 'C' })); // all agents

    expect(registry.getForAgent('openclaw')).toHaveLength(2);
    expect(registry.getForAgent('nanoclaw')).toHaveLength(2);
    expect(registry.getForAgent('picoclaw')).toHaveLength(1);
  });

  it('filters by platform', () => {
    const registry = new CheckRegistry();
    registry.register(makeMockCheck({ id: 'A', supportedPlatforms: ['darwin'] }));
    registry.register(makeMockCheck({ id: 'B', supportedPlatforms: ['linux'] }));
    registry.register(makeMockCheck({ id: 'C' })); // all platforms

    expect(registry.getForPlatform('darwin')).toHaveLength(2);
    expect(registry.getForPlatform('linux')).toHaveLength(2);
  });

  it('filters applicable by both agent and platform', () => {
    const registry = new CheckRegistry();
    registry.register(makeMockCheck({ id: 'A', supportedAgents: ['openclaw'], supportedPlatforms: ['darwin'] }));
    registry.register(makeMockCheck({ id: 'B', supportedAgents: ['nanoclaw'] }));
    registry.register(makeMockCheck({ id: 'C' }));

    expect(registry.getApplicable('openclaw', 'darwin')).toHaveLength(2); // A and C
    expect(registry.getApplicable('openclaw', 'linux')).toHaveLength(1); // only C
    expect(registry.getApplicable('nanoclaw', 'darwin')).toHaveLength(2); // B and C
  });

  it('reports count', () => {
    const registry = new CheckRegistry();
    expect(registry.count()).toBe(0);
    registry.register(makeMockCheck({ id: 'A' }));
    registry.register(makeMockCheck({ id: 'B' }));
    expect(registry.count()).toBe(2);
  });

  it('registerAll adds multiple', () => {
    const registry = new CheckRegistry();
    registry.registerAll([
      makeMockCheck({ id: 'A' }),
      makeMockCheck({ id: 'B' }),
      makeMockCheck({ id: 'C' }),
    ]);
    expect(registry.count()).toBe(3);
  });
});
