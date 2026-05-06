import { describe, expect, it } from 'vitest';
import { AdapterRegistry } from './registry.js';
import type { AgentAdapter } from './adapter.js';

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
