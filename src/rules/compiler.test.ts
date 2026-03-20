import { describe, it, expect } from 'vitest';
import { compileRule } from './compiler.js';
import type { DeclarativeRule } from './schema.js';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../core/types.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';

function makeContext(overrides?: Partial<ScanContext>): ScanContext {
  const config: ParsedConfig = {
    raw: '{"server": {"debug": true, "port": 8080}}',
    format: 'json',
    filePath: '/tmp/test-config.json',
    data: { server: { debug: true, port: 8080 } },
  };
  const installation: AgentInstallation = {
    agent: 'openclaw',
    installDir: '/tmp/test-agent',
    configFiles: [config],
  };
  return {
    installation,
    configs: [config],
    platform: 'darwin',
    fs: new LocalFSProvider(),
    ...overrides,
  };
}

describe('compileRule', () => {
  describe('config rules', () => {
    it('fails when config value matches dangerous value', async () => {
      const rule: DeclarativeRule = {
        id: 'T-001',
        name: 'Debug check',
        category: 'config',
        severity: 'warning',
        description: 'Debug is on',
        config: { path: 'server.debug', operator: 'eq', value: true },
      };

      const check = compileRule(rule);
      const result = await check.run(makeContext());

      expect(result.passed).toBe(false);
      expect(result.evidence).toHaveLength(1);
      expect(result.evidence![0].detail).toContain('true');
    });

    it('passes when config value does not match', async () => {
      const rule: DeclarativeRule = {
        id: 'T-002',
        name: 'Port check',
        category: 'config',
        severity: 'info',
        description: 'Port 80 is dangerous',
        config: { path: 'server.port', operator: 'eq', value: 80 },
      };

      const check = compileRule(rule);
      const result = await check.run(makeContext());

      expect(result.passed).toBe(true);
      expect(result.evidence).toBeUndefined();
    });

    it('supports pass_when: match', async () => {
      const rule: DeclarativeRule = {
        id: 'T-003',
        name: 'Debug must be false',
        category: 'config',
        severity: 'warning',
        description: 'Debug should be false',
        config: { path: 'server.debug', operator: 'eq', value: false, pass_when: 'match' },
      };

      const check = compileRule(rule);
      const result = await check.run(makeContext());

      // debug is true, so eq(true, false) = false, pass_when match means passed = false
      expect(result.passed).toBe(false);
    });

    it('handles exists operator', async () => {
      const rule: DeclarativeRule = {
        id: 'T-004',
        name: 'Auth must exist',
        category: 'config',
        severity: 'critical',
        description: 'Auth required',
        config: { path: 'auth.enabled', operator: 'exists', pass_when: 'match' },
      };

      const check = compileRule(rule);
      const result = await check.run(makeContext());

      // auth.enabled doesn't exist
      expect(result.passed).toBe(false);
    });

    it('sets fixable when fix.set is provided', async () => {
      const rule: DeclarativeRule = {
        id: 'T-005',
        name: 'Fix test',
        category: 'config',
        severity: 'warning',
        description: 'Fixable rule',
        config: { path: 'server.debug', operator: 'eq', value: true },
        fix: { set: 'server.debug', value: false },
      };

      const check = compileRule(rule);
      const result = await check.run(makeContext());

      expect(result.fixable).toBe(true);
      expect(check.fix).toBeDefined();
    });

    it('sets fixDescription from guidance', async () => {
      const rule: DeclarativeRule = {
        id: 'T-006',
        name: 'Guidance test',
        category: 'config',
        severity: 'info',
        description: 'With guidance',
        config: { path: 'server.debug', operator: 'eq', value: true },
        fix: { guidance: 'Turn it off' },
      };

      const check = compileRule(rule);
      const result = await check.run(makeContext());

      expect(result.fixDescription).toBe('Turn it off');
      expect(check.fix).toBeUndefined();
    });
  });

  describe('pattern rules', () => {
    it('finds regex matches in config files', async () => {
      const rule: DeclarativeRule = {
        id: 'T-010',
        name: 'Find debug',
        category: 'config',
        severity: 'warning',
        description: 'Debug in configs',
        pattern: { regex: 'debug', target: 'configs' },
      };

      const check = compileRule(rule);
      const result = await check.run(makeContext());

      expect(result.passed).toBe(false);
      expect(result.evidence!.length).toBeGreaterThan(0);
    });

    it('passes when no matches found', async () => {
      const rule: DeclarativeRule = {
        id: 'T-011',
        name: 'Find secret',
        category: 'config',
        severity: 'critical',
        description: 'Secrets in configs',
        pattern: { regex: 'AKIA[0-9A-Z]{16}', target: 'configs' },
      };

      const check = compileRule(rule);
      const result = await check.run(makeContext());

      expect(result.passed).toBe(true);
    });

    it('interpolates template variables in message', async () => {
      const rule: DeclarativeRule = {
        id: 'T-012',
        name: 'Template test',
        category: 'config',
        severity: 'info',
        description: 'Template',
        pattern: {
          regex: 'debug',
          target: 'configs',
          message: 'Found in {{file}} at line {{line}}: {{snippet}}',
        },
      };

      const check = compileRule(rule);
      const result = await check.run(makeContext());

      expect(result.passed).toBe(false);
      const detail = result.evidence![0].detail!;
      expect(detail).toContain('/tmp/test-config.json');
      expect(detail).toMatch(/line \d+/);
    });
  });

  describe('file_exists rules', () => {
    it('fails when file exists and pass_when is not-exists', async () => {
      const rule: DeclarativeRule = {
        id: 'T-020',
        name: 'No package.json',
        category: 'config',
        severity: 'info',
        description: 'File should not exist',
        file_exists: { path: '/tmp', pass_when: 'not-exists' },
      };

      const check = compileRule(rule);
      const result = await check.run(makeContext());

      // /tmp exists
      expect(result.passed).toBe(false);
    });

    it('passes when file does not exist and pass_when is not-exists', async () => {
      const rule: DeclarativeRule = {
        id: 'T-021',
        name: 'No secret file',
        category: 'config',
        severity: 'warning',
        description: 'Secret file check',
        file_exists: { path: '/tmp/nonexistent-vaso-test-file-xyz', pass_when: 'not-exists' },
      };

      const check = compileRule(rule);
      const result = await check.run(makeContext());

      expect(result.passed).toBe(true);
    });

    it('resolves relative paths from installDir', async () => {
      const rule: DeclarativeRule = {
        id: 'T-022',
        name: 'Relative path',
        category: 'config',
        severity: 'info',
        description: 'Relative path test',
        file_exists: { path: 'nonexistent.txt', pass_when: 'not-exists' },
      };

      const check = compileRule(rule);
      const result = await check.run(makeContext());

      expect(result.passed).toBe(true);
    });
  });

  describe('metadata', () => {
    it('sets supportedAgents from rule', () => {
      const rule: DeclarativeRule = {
        id: 'T-030',
        name: 'Agents',
        category: 'config',
        severity: 'info',
        description: 'Agent filter',
        agents: ['openclaw', 'nanoclaw'],
        config: { path: 'a', operator: 'exists' },
      };

      const check = compileRule(rule);
      expect(check.supportedAgents).toEqual(['openclaw', 'nanoclaw']);
    });

    it('sets supportedPlatforms from rule', () => {
      const rule: DeclarativeRule = {
        id: 'T-031',
        name: 'Platforms',
        category: 'config',
        severity: 'info',
        description: 'Platform filter',
        platforms: ['darwin', 'linux'],
        config: { path: 'a', operator: 'exists' },
      };

      const check = compileRule(rule);
      expect(check.supportedPlatforms).toEqual(['darwin', 'linux']);
    });
  });
});
