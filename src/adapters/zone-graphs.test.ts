import { describe, it, expect } from 'vitest';
import { CheckRegistry } from '../core/check-registry.js';
import { AdapterRegistry } from '../adapters/registry.js';
import { validateAllZoneGraphs, validateZoneGraph } from '../core/zone-graph-validator.js';
import { defaultZoneGraph } from '../core/default-zone-graph.js';
import { configChecks } from '../checks/config/index.js';
import { skillChecks } from '../checks/skills/index.js';
import { iocChecks } from '../checks/ioc/index.js';
import { networkChecks } from '../checks/network/index.js';
import { runtimeChecks } from '../checks/runtime/index.js';
import { mcpChecks } from '../checks/mcp/index.js';
import { openclawChecks } from '../checks/openclaw/index.js';
import { nanoclawChecks } from '../checks/nanoclaw/index.js';
import { ironclawChecks } from '../checks/ironclaw/index.js';
import { nanobotChecks } from '../checks/nanobot/index.js';
import { zeroclawChecks } from '../checks/zeroclaw/index.js';
import { lyrieChecks } from '../checks/lyrie/index.js';
import { hermesChecks } from '../checks/hermes/index.js';
import { policyChecks } from '../checks/policy/index.js';
import { advisoryChecks } from '../checks/advisory/index.js';
import { claudeCodeChecks } from '../checks/claude-code/index.js';
import { codexChecks } from '../checks/codex/index.js';
import { opencodeChecks } from '../checks/opencode/index.js';
import { openclawAdapter } from './openclaw.js';
import { nanoclawAdapter } from './nanoclaw.js';
import { picoclawAdapter } from './picoclaw.js';
import { ironclawAdapter } from './ironclaw.js';
import { nanobotAdapter } from './nanobot.js';
import { zeroclawAdapter } from './zeroclaw.js';
import { nemoclawAdapter } from './nemoclaw.js';
import { hermesAdapter } from './hermes.js';
import { lyrieAdapter } from './lyrie.js';
import { claudeCodeAdapter } from './claude-code.js';
import { codexAdapter } from './codex.js';
import { opencodeAdapter } from './opencode.js';

function makeFullRegistries() {
  const checks = new CheckRegistry();
  for (const set of [
    configChecks, skillChecks, iocChecks, networkChecks, runtimeChecks,
    mcpChecks, openclawChecks, nanoclawChecks, ironclawChecks, nanobotChecks,
    zeroclawChecks, lyrieChecks, hermesChecks, policyChecks, advisoryChecks, claudeCodeChecks, codexChecks,
    opencodeChecks,
  ]) {
    checks.registerAll(set);
  }
  const adapters = new AdapterRegistry();
  for (const a of [
    openclawAdapter, nanoclawAdapter, picoclawAdapter, ironclawAdapter,
    nanobotAdapter, zeroclawAdapter, nemoclawAdapter, hermesAdapter, lyrieAdapter,
    claudeCodeAdapter, codexAdapter, opencodeAdapter,
  ]) {
    adapters.register(a);
  }
  return { adapters, checks };
}

describe('adapter ZoneGraphs (real check registry)', () => {
  it('every adapter graph (custom or fallback) validates against the real check registry', () => {
    const { adapters, checks } = makeFullRegistries();
    const errors = validateAllZoneGraphs(adapters, checks, defaultZoneGraph);
    expect(errors).toEqual([]);
  });

  it.each([
    ['nemoclaw', nemoclawAdapter, 5],
    ['ironclaw', ironclawAdapter, 4],
    ['nanobot', nanobotAdapter, 4],
    ['lyrie', lyrieAdapter, 5],
    ['claude-code', claudeCodeAdapter, 4],
    ['codex', codexAdapter, 4],
    ['opencode', opencodeAdapter, 4],
  ] as const)('%s graph has the expected zone count', (_name, adapter, zoneCount) => {
    const graph = adapter.getZoneGraph?.();
    expect(graph).toBeDefined();
    expect(graph!.zones).toHaveLength(zoneCount);
  });

  it.each([
    ['openclaw', openclawAdapter],
    ['nanoclaw', nanoclawAdapter],
    ['picoclaw', picoclawAdapter],
    ['zeroclaw', zeroclawAdapter],
  ] as const)('%s does not declare a custom graph (uses fallback)', (_name, adapter) => {
    expect(adapter.getZoneGraph).toBeUndefined();
  });

  it('every custom graph declares at least one inversion edge', () => {
    const customAdapters = [
      nemoclawAdapter, ironclawAdapter, nanobotAdapter, lyrieAdapter, hermesAdapter,
      claudeCodeAdapter, codexAdapter, opencodeAdapter,
    ];
    for (const adapter of customAdapters) {
      const graph = adapter.getZoneGraph!();
      const inversions = graph.edges.filter(e => e.triggerCheckIds && e.triggerCheckIds.length > 0);
      expect(inversions.length).toBeGreaterThan(0);
    }
  });

  it('every custom graph individually validates', () => {
    const { checks } = makeFullRegistries();
    const knownIds = new Set(checks.getAll().map(c => c.id));
    const customAdapters = [
      ['nemoclaw', nemoclawAdapter],
      ['ironclaw', ironclawAdapter],
      ['nanobot', nanobotAdapter],
      ['lyrie', lyrieAdapter],
      ['hermes', hermesAdapter],
      ['claude-code', claudeCodeAdapter],
      ['codex', codexAdapter],
      ['opencode', opencodeAdapter],
    ] as const;
    for (const [name, adapter] of customAdapters) {
      const graph = adapter.getZoneGraph!();
      const errors = validateZoneGraph(graph, knownIds, name);
      expect(errors, `${name}: ${JSON.stringify(errors)}`).toEqual([]);
    }
  });
});
