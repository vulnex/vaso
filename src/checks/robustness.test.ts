import { describe, it, expect, beforeAll } from 'vitest';
import type { AgentInstallation, AgentType, ParsedConfig, ScanContext } from '../core/types.js';
import { AGENT_TYPES } from '../core/types.js';
import { SnapshotFSProvider } from '../core/snapshot-fs-provider.js';
import { checkRegistry } from '../core/check-registry.js';
import { registerAllChecks } from './index.js';

// Every check must survive hostile config shapes (nulls, arrays and scalars
// where objects are expected) without throwing — a throw surfaces as
// an errored check and an incomplete scan.
const HOME = '/home/test';

function emptyFs(): SnapshotFSProvider {
  return new SnapshotFSProvider({
    version: 1, hostname: 'test-host', platform: 'linux', homedir: HOME, timestamp: '2026-09-29T00:00:00Z',
    privilege: { uid: 1000, username: 'test', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['test'], skippedPaths: [] },
    files: {}, directories: {}, directoryModes: {}, commandOutputs: {}, env: {},
  });
}

// The config loader turns a non-mapping top level into {} (see
// config-loader.test.ts), so hostile values only occur below the top level.
const SHAPES: unknown[] = [
  {},
  { gateway: null, channels: null, tools: null, agents: null, mcpServers: null, permissions: null },
  { gateway: [], channels: [1, null], tools: 'x', agents: { defaults: null, list: 'x' }, mcpServers: { a: null, b: 3 } },
  { channel_list: { a: null, b: { enabled: true, allow_from: null, settings: null } }, providers: { x: null } },
];

function configsFor(dir: string): ParsedConfig[] {
  const out: ParsedConfig[] = [];
  SHAPES.forEach((data, i) => {
    for (const [format, ext] of [['json', 'json'], ['toml', 'toml'], ['yaml', 'yaml'], ['env', 'env']] as const) {
      out.push({ raw: JSON.stringify(data), format, filePath: `${dir}/c${i}.${ext}`, data } as unknown as ParsedConfig);
    }
  });
  return out;
}

describe('check robustness', () => {
  beforeAll(() => {
    if (checkRegistry.getAll().length === 0) registerAllChecks();
  });

  const agents = AGENT_TYPES.filter(a => a !== 'mcp' && a !== 'skill-audit') as AgentType[];

  it.each(agents)('no check throws on hostile config shapes for %s', async (agent) => {
    const dir = `${HOME}/.${agent}`;
    const configs = configsFor(dir);
    const installation: AgentInstallation = { agent, installDir: dir, configFiles: configs, version: '1.0.0' };
    const ctx: ScanContext = { installation, configs, platform: 'linux', fs: emptyFs() };
    const failures: string[] = [];
    for (const check of checkRegistry.getAll()) {
      if (check.supportedAgents && !check.supportedAgents.includes(agent)) continue;
      if (check.excludedAgents?.includes(agent)) continue;
      try {
        await check.run(ctx);
      } catch (err) {
        failures.push(`${check.id}: ${(err as Error).message}`);
      }
    }
    expect(failures).toEqual([]);
  });
});
