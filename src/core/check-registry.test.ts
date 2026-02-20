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
    console.log(`[CheckRegistry] registered check: ${registry.getAll()[0].id}, total: ${registry.getAll().length}`);
    expect(registry.getAll()).toHaveLength(1);
    expect(registry.getAll()[0].id).toBe('MOCK-001');
  });

  it('prevents duplicate registration', () => {
    const registry = new CheckRegistry();
    registry.register(makeMockCheck());
    console.log('[CheckRegistry] attempting duplicate registration of MOCK-001');
    expect(() => registry.register(makeMockCheck())).toThrow('already registered');
    console.log('[CheckRegistry] duplicate correctly rejected');
  });

  it('filters by category', () => {
    const registry = new CheckRegistry();
    registry.register(makeMockCheck({ id: 'CFG-001', category: 'config' }));
    registry.register(makeMockCheck({ id: 'SKL-001', category: 'skills' }));
    const configChecks = registry.getByCategory('config');
    const skillsChecks = registry.getByCategory('skills');
    const iocChecks = registry.getByCategory('ioc');
    console.log(`[CheckRegistry] category filter → config: ${configChecks.length}, skills: ${skillsChecks.length}, ioc: ${iocChecks.length}`);
    expect(configChecks).toHaveLength(1);
    expect(skillsChecks).toHaveLength(1);
    expect(iocChecks).toHaveLength(0);
  });

  it('filters by agent', () => {
    const registry = new CheckRegistry();
    registry.register(makeMockCheck({ id: 'A', supportedAgents: ['openclaw'] }));
    registry.register(makeMockCheck({ id: 'B', supportedAgents: ['nanoclaw'] }));
    registry.register(makeMockCheck({ id: 'C' })); // all agents
    const oc = registry.getForAgent('openclaw');
    const nc = registry.getForAgent('nanoclaw');
    const pc = registry.getForAgent('picoclaw');
    console.log(`[CheckRegistry] agent filter → openclaw: ${oc.length} [${oc.map(c => c.id)}], nanoclaw: ${nc.length} [${nc.map(c => c.id)}], picoclaw: ${pc.length} [${pc.map(c => c.id)}]`);
    expect(oc).toHaveLength(2);
    expect(nc).toHaveLength(2);
    expect(pc).toHaveLength(1);
  });

  it('filters by platform', () => {
    const registry = new CheckRegistry();
    registry.register(makeMockCheck({ id: 'A', supportedPlatforms: ['darwin'] }));
    registry.register(makeMockCheck({ id: 'B', supportedPlatforms: ['linux'] }));
    registry.register(makeMockCheck({ id: 'C' })); // all platforms
    const darwin = registry.getForPlatform('darwin');
    const linux = registry.getForPlatform('linux');
    console.log(`[CheckRegistry] platform filter → darwin: ${darwin.length} [${darwin.map(c => c.id)}], linux: ${linux.length} [${linux.map(c => c.id)}]`);
    expect(darwin).toHaveLength(2);
    expect(linux).toHaveLength(2);
  });

  it('filters applicable by both agent and platform', () => {
    const registry = new CheckRegistry();
    registry.register(makeMockCheck({ id: 'A', supportedAgents: ['openclaw'], supportedPlatforms: ['darwin'] }));
    registry.register(makeMockCheck({ id: 'B', supportedAgents: ['nanoclaw'] }));
    registry.register(makeMockCheck({ id: 'C' }));
    const ocDarwin = registry.getApplicable('openclaw', 'darwin');
    const ocLinux = registry.getApplicable('openclaw', 'linux');
    const ncDarwin = registry.getApplicable('nanoclaw', 'darwin');
    console.log(`[CheckRegistry] applicable → openclaw+darwin: ${ocDarwin.length} [${ocDarwin.map(c => c.id)}], openclaw+linux: ${ocLinux.length} [${ocLinux.map(c => c.id)}], nanoclaw+darwin: ${ncDarwin.length} [${ncDarwin.map(c => c.id)}]`);
    expect(ocDarwin).toHaveLength(2); // A and C
    expect(ocLinux).toHaveLength(1); // only C
    expect(ncDarwin).toHaveLength(2); // B and C
  });

  it('reports count', () => {
    const registry = new CheckRegistry();
    console.log(`[CheckRegistry] initial count: ${registry.count()}`);
    registry.register(makeMockCheck({ id: 'A' }));
    registry.register(makeMockCheck({ id: 'B' }));
    console.log(`[CheckRegistry] after 2 registrations: ${registry.count()}`);
    expect(registry.count()).toBe(2);
  });

  it('registerAll adds multiple', () => {
    const registry = new CheckRegistry();
    registry.registerAll([
      makeMockCheck({ id: 'A' }),
      makeMockCheck({ id: 'B' }),
      makeMockCheck({ id: 'C' }),
    ]);
    console.log(`[CheckRegistry] registerAll → count: ${registry.count()}, ids: ${registry.getAll().map(c => c.id).join(', ')}`);
    expect(registry.count()).toBe(3);
  });
});
