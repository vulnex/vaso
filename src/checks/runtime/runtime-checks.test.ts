import { describe, it, expect } from 'vitest';
import type { ScanContext, AgentInstallation } from '../../core/types.js';
import { run005 } from './run-005-process-ancestry.js';

function makeContext(): ScanContext {
  const installation: AgentInstallation = {
    agent: 'openclaw',
    installDir: '/tmp/test-openclaw',
    configFiles: [],
  };
  return { installation, configs: [], platform: process.platform as NodeJS.Platform };
}

describe('RUN-005: Process Ancestry Analysis', () => {
  it('returns a valid CheckResult', async () => {
    const result = await run005.run(makeContext());
    expect(result.id).toBe('RUN-005');
    expect(result.category).toBe('runtime');
    expect(result.severity).toBe('warning');
    expect(typeof result.passed).toBe('boolean');
    expect(typeof result.message).toBe('string');
  });

  it('is limited to darwin and linux platforms', () => {
    expect(run005.supportedPlatforms).toEqual(['darwin', 'linux']);
  });

  it('passes when no agent processes are running', async () => {
    // In a test environment, no openclaw/nanoclaw/etc processes should be running
    const result = await run005.run(makeContext());
    expect(result.passed).toBe(true);
  });
});
