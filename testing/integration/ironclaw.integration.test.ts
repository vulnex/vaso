import { describe, it, expect, beforeAll } from 'vitest';
import type { ScanResult } from '../../src/core/types.js';
import {
  runVasoScan,
  getAgentResult,
  expectCheckFailed,
  expectCheckPassed,
} from './helpers.js';

describe('IronClaw 1.x (Reborn) Insecure', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/ironclaw.Dockerfile',
      buildArgs: { SCENARIO: 'insecure', LAYOUT: 'reborn' },
    });
  });

  it('should detect the IronClaw Reborn installation', () => {
    const agent = getAgentResult(result, 'ironclaw');
    expect(agent).toBeDefined();
    expect(agent!.installation.installDir).toBe('/root/.ironclaw/reborn');
    expect(agent!.installation.version).toBe('1.4.0');
  });

  it('should detect the WebChat listener on 0.0.0.0 (IC-001)', () => {
    expect(expectCheckFailed(result, 'IC-001').severity).toBe('warning');
  });

  it('should detect the cleartext LLM endpoint (IC-002)', () => {
    expect(expectCheckFailed(result, 'IC-002').severity).toBe('warning');
  });

  it('should detect the world-readable webui-token (IC-004)', () => {
    expect(expectCheckFailed(result, 'IC-004').severity).toBe('critical');
  });

  it('should detect the local-dev-yolo profile (IC-006)', () => {
    expect(expectCheckFailed(result, 'IC-006').severity).toBe('critical');
  });

  it('should report the minimal approval policy (IC-007) as info — 1.4 parses [policy] but does not enforce it', () => {
    expect(expectCheckFailed(result, 'IC-007').severity).toBe('info');
  });

  it('should detect the world-readable master key (IC-009)', () => {
    expect(expectCheckFailed(result, 'IC-009').severity).toBe('critical');
  });

  it('should detect permissive CORS origins (IC-013)', () => {
    expect(expectCheckFailed(result, 'IC-013').severity).toBe('warning');
  });

  it('should detect the world-readable state database (IC-014)', () => {
    expect(expectCheckFailed(result, 'IC-014').severity).toBe('warning');
  });

  it('should assign a failing grade', () => {
    const agent = getAgentResult(result, 'ironclaw');
    expect(agent!.score).toBeLessThan(30);
    expect(agent!.grade).toBe('F');
  });
});

describe('IronClaw 1.x (Reborn) Secure', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/ironclaw.Dockerfile',
      buildArgs: { SCENARIO: 'secure', LAYOUT: 'reborn' },
    });
  });

  it('should pass every IronClaw check on a stock onboard config', () => {
    for (const id of ['IC-001', 'IC-002', 'IC-004', 'IC-006', 'IC-007', 'IC-009', 'IC-013', 'IC-014']) {
      expectCheckPassed(result, id);
    }
  });

  it('should produce a high security score', () => {
    const agent = getAgentResult(result, 'ironclaw');
    expect(agent).toBeDefined();
    expect(agent!.score).toBeGreaterThanOrEqual(70);
  });
});

describe('IronClaw 0.x (legacy) Insecure', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/ironclaw.Dockerfile',
      buildArgs: { SCENARIO: 'insecure', LAYOUT: 'legacy' },
    });
  });

  it('should detect the legacy installation', () => {
    const agent = getAgentResult(result, 'ironclaw');
    expect(agent).toBeDefined();
    expect(agent!.installation.profile).toBe('legacy');
    expect(agent!.installation.version).toBe('0.29.1');
  });

  it('should detect legacy misconfigurations', () => {
    expect(expectCheckFailed(result, 'IC-001').severity).toBe('warning');   // HTTP_HOST / GATEWAY_HOST 0.0.0.0
    expect(expectCheckFailed(result, 'IC-002').severity).toBe('warning');   // OLLAMA_BASE_URL http:// LAN
    expect(expectCheckFailed(result, 'IC-004').severity).toBe('warning');   // gateway token in config.toml
    expect(expectCheckFailed(result, 'IC-005').severity).toBe('warning');   // SANDBOX_ENABLED=false
    expect(expectCheckFailed(result, 'IC-006').severity).toBe('critical');  // full_access + allow
    expect(expectCheckFailed(result, 'IC-007').severity).toBe('critical');  // AGENT_AUTO_APPROVE_TOOLS
    expect(expectCheckFailed(result, 'IC-008').severity).toBe('warning');   // ALLOW_LOCAL_TOOLS
    expect(expectCheckFailed(result, 'IC-009').severity).toBe('critical');  // SECRETS_MASTER_KEY in .env
    expect(expectCheckFailed(result, 'IC-010').severity).toBe('warning');   // telegram without owner
    expect(expectCheckFailed(result, 'IC-011').severity).toBe('warning');   // wildcard domains
    expect(expectCheckFailed(result, 'IC-012').severity).toBe('warning');   // auto-pull by tag
    expect(expectCheckFailed(result, 'IC-014').severity).toBe('warning');   // world-readable ironclaw.db
  });
});

describe('IronClaw 0.x (legacy) Secure', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/ironclaw.Dockerfile',
      buildArgs: { SCENARIO: 'secure', LAYOUT: 'legacy' },
    });
  });

  it('should pass the legacy IronClaw checks', () => {
    for (const id of ['IC-001', 'IC-005', 'IC-006', 'IC-007', 'IC-008', 'IC-009', 'IC-011', 'IC-012']) {
      expectCheckPassed(result, id);
    }
  });
});
