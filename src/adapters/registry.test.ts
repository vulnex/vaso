import { describe, expect, it } from 'vitest';
import { AdapterRegistry, normalizeVersions } from './registry.js';
import type { AgentAdapter } from './adapter.js';
import type { AgentInstallation } from '../core/types.js';

function adapter(name: AgentAdapter['agent'], detect: AgentAdapter['detect']): AgentAdapter {
  return {
    agent: name,
    displayName: name,
    detect,
    getConfigPaths() { return []; },
    getSkillsDir() { return undefined; },
    getGatewayInfo() { return undefined; },
  };
}

describe('AdapterRegistry', () => {
  it('returns installations and detection errors separately', async () => {
    const registry = new AdapterRegistry();
    registry.register(adapter('openclaw', async () => [{
      agent: 'openclaw',
      installDir: '/tmp/openclaw',
      configFiles: [],
    }]));
    registry.register(adapter('codex', async () => {
      throw new Error('bad config parse');
    }));

    const result = await registry.detectAllDetailed();

    expect(result.installations).toHaveLength(1);
    expect(result.installations[0].agent).toBe('openclaw');
    expect(result.errors).toEqual([{
      agent: 'codex',
      displayName: 'codex',
      message: 'bad config parse',
    }]);
  });

  it('keeps detectAll backward compatible by returning only installations', async () => {
    const registry = new AdapterRegistry();
    registry.register(adapter('openclaw', async () => [{
      agent: 'openclaw',
      installDir: '/tmp/openclaw',
      configFiles: [],
    }]));
    registry.register(adapter('codex', async () => {
      throw new Error('bad config parse');
    }));

    const installations = await registry.detectAll();

    expect(installations).toHaveLength(1);
    expect(installations[0].agent).toBe('openclaw');
  });
});

const base = { agent: 'picoclaw', installDir: '/h/.picoclaw', configPaths: [] } as unknown as AgentInstallation;

describe('normalizeVersions', () => {
  it('coerces a numeric version (e.g. a config schema number) to a string', () => {
    expect(normalizeVersions({ ...base, version: 3 as unknown as string }).version).toBe('3');
  });

  it('drops non-scalar versions and blank strings', () => {
    expect(normalizeVersions({ ...base, version: { a: 1 } as unknown as string }).version).toBeUndefined();
    expect(normalizeVersions({ ...base, version: '  ' }).version).toBeUndefined();
  });

  it('normalizes other installs too', () => {
    const inst = normalizeVersions({ ...base, version: '1.0.0', otherInstalls: [{ path: '/x', version: 2 as unknown as string }] });
    expect(inst.otherInstalls?.[0].version).toBe('2');
  });
});
