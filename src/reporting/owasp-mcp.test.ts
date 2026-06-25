import { describe, it, expect } from 'vitest';
import type { ScanResult, CheckModule } from '../core/types.js';
import {
  owaspMcpForCheckId,
  applyOwaspTags,
  computeOwaspMcpCoverage,
  hasOwaspMcpFindings,
  renderOwaspMcpCoverageMarkdown,
} from './owasp-mcp.js';

function resultWith(findings: { id: string; passed: boolean }[]): ScanResult {
  return {
    timestamp: '2026-06-05T00:00:00Z',
    agents: [
      {
        agent: 'mcp',
        installation: { agent: 'mcp', installDir: '/tmp', configFiles: [] },
        results: findings.map((f) => ({
          id: f.id,
          name: f.id,
          category: 'mcp' as const,
          severity: 'warning' as const,
          passed: f.passed,
          message: '',
        })),
        score: 0,
        grade: 'F' as const,
      },
    ],
    totalScore: 0,
    totalGrade: 'F',
    fleetAverage: 0,
    summary: { critical: 0, warning: 0, info: 0, passed: 0, total: 0 },
  };
}

describe('owaspMcpForCheckId', () => {
  it('maps representative checks to their OWASP MCP risk', () => {
    expect(owaspMcpForCheckId('MCP-024')).toBe('MCP03');
    expect(owaspMcpForCheckId('MCP-029')).toBe('MCP07');
    expect(owaspMcpForCheckId('MCP-005')).toBe('MCP05');
    expect(owaspMcpForCheckId('CD-003')).toBe('MCP04');
  });

  it('returns undefined for unmapped checks', () => {
    expect(owaspMcpForCheckId('CFG-001')).toBeUndefined();
  });
});

describe('applyOwaspTags', () => {
  it('tags modules from the central map', () => {
    const checks = [{ id: 'MCP-024' }, { id: 'CFG-001' }] as unknown as CheckModule[];
    applyOwaspTags(checks);
    expect(checks[0].owaspMcp).toBe('MCP03');
    expect(checks[1].owaspMcp).toBeUndefined();
  });
});

describe('computeOwaspMcpCoverage', () => {
  it('buckets findings by risk and counts failures', () => {
    const rows = computeOwaspMcpCoverage(
      resultWith([
        { id: 'MCP-024', passed: false }, // MCP03
        { id: 'MCP-025', passed: true }, // MCP03
        { id: 'MCP-029', passed: false }, // MCP07
      ]),
    );
    const mcp03 = rows.find((r) => r.id === 'MCP03')!;
    expect(mcp03.checks).toEqual(['MCP-024', 'MCP-025']);
    expect(mcp03.failed).toBe(1);
    expect(mcp03.covered).toBe(true);

    const mcp06 = rows.find((r) => r.id === 'MCP06')!;
    expect(mcp06.covered).toBe(false); // runtime risk, not statically covered here
  });

  it('always returns all ten risks', () => {
    expect(computeOwaspMcpCoverage(resultWith([])).length).toBe(10);
  });
});

describe('rendering', () => {
  it('renders a coverage table when MCP findings exist', () => {
    const result = resultWith([{ id: 'MCP-024', passed: false }]);
    expect(hasOwaspMcpFindings(result)).toBe(true);
    const md = renderOwaspMcpCoverageMarkdown(result);
    expect(md).toContain('OWASP MCP Top 10 Coverage');
    expect(md).toContain('MCP03');
  });

  it('renders nothing when there are no MCP findings', () => {
    const result = resultWith([{ id: 'CFG-001', passed: false }]);
    expect(hasOwaspMcpFindings(result)).toBe(false);
    expect(renderOwaspMcpCoverageMarkdown(result)).toBe('');
  });
});
