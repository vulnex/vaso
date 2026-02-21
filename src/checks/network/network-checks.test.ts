import { describe, it, expect } from 'vitest';
import type { ScanContext, AgentInstallation } from '../../core/types.js';
import { net005 } from './net-005-active-connections.js';

function makeContext(): ScanContext {
  const installation: AgentInstallation = {
    agent: 'openclaw',
    installDir: '/tmp/test-openclaw',
    configFiles: [],
  };
  return { installation, configs: [], platform: process.platform as NodeJS.Platform };
}

describe('NET-005: Active Connection Monitoring', () => {
  it('returns a valid CheckResult', async () => {
    const result = await net005.run(makeContext());
    expect(result.id).toBe('NET-005');
    expect(result.category).toBe('network');
    expect(result.severity).toBe('critical');
    expect(typeof result.passed).toBe('boolean');
    expect(typeof result.message).toBe('string');
  });

  it('is limited to darwin and linux platforms', () => {
    expect(net005.supportedPlatforms).toEqual(['darwin', 'linux']);
  });
});
