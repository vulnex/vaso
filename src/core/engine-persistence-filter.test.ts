import { describe, it, expect } from 'vitest';
import { ScanEngine } from './engine.js';
import { CheckRegistry } from './check-registry.js';
import { AdapterRegistry } from '../adapters/registry.js';
import type { AgentType, CheckModule, CheckResult, ScanContext } from './types.js';
import type { AgentAdapter } from '../adapters/adapter.js';
import type { FSProvider } from './fs-provider.js';

// dt25 g1-F2: with `-a <agent>`, a service another detected (not selected)
// agent owns must leave the scanned agent's warnings, as in a full scan.

function adapter(agent: AgentType): AgentAdapter {
  return {
    agent,
    displayName: agent,
    async detect() { return [{ agent, installDir: `/home/test/.${agent}`, configFiles: [] }]; },
    getConfigPaths() { return []; },
    getSkillsDir() { return undefined; },
    getGatewayInfo() { return undefined; },
  };
}

/** RUN-001 stand-in: the gateway unit is OpenClaw's own; the dropper is nobody's. */
const run001: CheckModule = {
  id: 'RUN-001',
  name: 'Unauthorized LaunchAgents',
  category: 'runtime',
  severity: 'warning',
  description: 'test',
  async run(ctx: ScanContext): Promise<CheckResult> {
    const own = ctx.installation.agent === 'openclaw';
    return {
      id: 'RUN-001', name: 'Unauthorized LaunchAgents', category: 'runtime', severity: 'warning', passed: false,
      message: 'Found persistence',
      evidence: [
        own
          ? { file: '/u/openclaw-gateway.service', detail: 'Systemd service for an installed agent', mitigated: true }
          : { file: '/u/openclaw-gateway.service', detail: 'Systemd service references "openclaw"' },
        { file: '/u/evil-claw.service', detail: 'Systemd service references "claw"' },
      ],
    };
  },
};

const fs = {
  platform: 'linux',
  async readFile() { throw new Error('ENOENT'); },
  async readBytes() { return new Uint8Array(); },
  async readdir() { return []; },
  async readdirEntries() { return []; },
  async access() { return false; },
  async stat() { throw new Error('ENOENT'); },
  async realpath(p: string) { return p; },
  async exec() { return { stdout: '', stderr: '', exitCode: 0 }; },
  execSync() { return ''; },
  getEnv() { return undefined; },
  homedir() { return '/home/test'; },
} as unknown as FSProvider;

describe('ScanEngine -a: persistence owned by another detected agent', () => {
  it('drops the other agent\'s own service from the selected agent and keeps the unowned one', async () => {
    const adapters = new AdapterRegistry();
    adapters.register(adapter('openclaw'));
    adapters.register(adapter('nanoclaw'));
    const checks = new CheckRegistry();
    checks.register(run001);
    const engine = new ScanEngine(adapters, checks, fs);

    const filtered = await engine.scan({ agentFilter: 'nanoclaw' });
    expect(filtered.agents.map(a => a.agent)).toEqual(['nanoclaw']);
    const r = filtered.agents[0].results.find(x => x.id === 'RUN-001')!;
    expect(r.evidence?.map(e => e.file)).toEqual(['/u/evil-claw.service']);
    expect(r.message).toContain('1 more runs another detected agent, reported under openclaw');

    // the same verdict as the full scan gives nanoclaw
    const full = await engine.scan({});
    const nano = full.agents.find(a => a.agent === 'nanoclaw')!.results.find(x => x.id === 'RUN-001')!;
    expect(nano.evidence).toEqual(r.evidence);
  });
});
