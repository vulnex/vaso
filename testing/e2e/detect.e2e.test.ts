import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createE2EEnvironment, type E2EEnvironment } from './helpers/setup.js';
import { runVasoCLI, runVasoJSONArray } from './helpers/cli-runner.js';
import type { AgentInstallation } from '../../src/core/types.js';

describe('E2E: vaso detect', () => {
  let env: E2EEnvironment;

  beforeAll(async () => {
    env = await createE2EEnvironment({
      scenario: 'insecure',
    });
  });

  afterAll(async () => {
    await env.cleanup();
  });

  it('should detect all 6 agents with --format json', async () => {
    const installations = await runVasoJSONArray(
      ['detect'],
      { HOME: env.tempHome },
    ) as AgentInstallation[];

    expect(installations.length).toBeGreaterThanOrEqual(6);

    const agentTypes = installations.map(i => i.agent);
    expect(agentTypes).toContain('openclaw');
    expect(agentTypes).toContain('nanoclaw');
    expect(agentTypes).toContain('picoclaw');
    expect(agentTypes).toContain('ironclaw');
    expect(agentTypes).toContain('nanobot');
    expect(agentTypes).toContain('zeroclaw');
  });

  it('should filter by --agent openclaw', async () => {
    const installations = await runVasoJSONArray(
      ['detect', '--agent', 'openclaw'],
      { HOME: env.tempHome },
    ) as AgentInstallation[];

    expect(installations.length).toBeGreaterThanOrEqual(1);
    for (const inst of installations) {
      expect(inst.agent).toBe('openclaw');
    }
  });

  it('should show agent names in terminal output', async () => {
    const result = await runVasoCLI(
      ['detect'],
      { HOME: env.tempHome },
    );

    const output = result.stdout;
    expect(output).toContain('openclaw');
    expect(output).toContain('nanoclaw');
    expect(output).toContain('picoclaw');
    expect(output).toContain('ironclaw');
    expect(output).toContain('nanobot');
    expect(output).toContain('zeroclaw');
  });

  it('should have installDir paths pointing to temp HOME', async () => {
    const installations = await runVasoJSONArray(
      ['detect'],
      { HOME: env.tempHome },
    ) as AgentInstallation[];

    for (const inst of installations) {
      expect(inst.installDir).toContain(env.tempHome);
    }
  });
});
