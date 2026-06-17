import { describe, it, expect } from 'vitest';
import type { ScanResult, CheckModule } from '../core/types.js';
import { checkRegistry } from '../core/check-registry.js';
import { registerAllChecks } from '../checks/index.js';
import {
  owaspAgenticForCheckId,
  applyAgenticTags,
  computeOwaspAgenticCoverage,
  hasOwaspAgenticFindings,
  renderOwaspAgenticCoverageMarkdown,
  CHECK_AGENTIC_MAP,
  OWASP_AGENTIC_TITLES,
} from './owasp-agentic.js';

function resultWith(findings: { id: string; passed: boolean }[]): ScanResult {
  return {
    timestamp: '2026-06-09T00:00:00Z',
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
    summary: { critical: 0, warning: 0, info: 0, passed: 0, total: 0 },
  };
}

describe('owaspAgenticForCheckId', () => {
  it('maps representative checks to their Agentic AI risk(s)', () => {
    expect(owaspAgenticForCheckId('MCP-024')).toEqual(['AAI003']);
    expect(owaspAgenticForCheckId('ADV-001')).toEqual(['AAI009']);
    expect(owaspAgenticForCheckId('MCP-001')).toEqual(['AAI007']);
  });

  it('returns multiple risks for dual-tagged checks (most-relevant first)', () => {
    // A YOLO/auto-approve setting both removes the checker and grants authority.
    expect(owaspAgenticForCheckId('CC-001')).toEqual(['AAI012', 'AAI001']);
    // Sandbox/exec scope: enables critical interaction and widens blast radius.
    expect(owaspAgenticForCheckId('MCP-022')).toEqual(['AAI002', 'AAI005', 'AAI009']);
  });

  it('returns an empty array for deliberately unmapped checks', () => {
    expect(owaspAgenticForCheckId('CG-001')).toEqual([]); // PII at rest, no clean home
    expect(owaspAgenticForCheckId('SKL-012')).toEqual([]); // complexity metric
    expect(owaspAgenticForCheckId('NOPE-999')).toEqual([]);
  });
});

describe('applyAgenticTags', () => {
  it('tags modules from the central map', () => {
    const checks = [{ id: 'CC-001' }, { id: 'CG-001' }] as unknown as CheckModule[];
    applyAgenticTags(checks);
    expect(checks[0].owaspAgentic).toEqual(['AAI012', 'AAI001']);
    expect(checks[1].owaspAgentic).toBeUndefined();
  });
});

describe('computeOwaspAgenticCoverage', () => {
  it('buckets a multi-tagged finding into every risk it maps to', () => {
    const rows = computeOwaspAgenticCoverage(
      resultWith([
        { id: 'CC-001', passed: false }, // AAI012 + AAI001
        { id: 'MCP-024', passed: true }, // AAI003
      ]),
    );
    const aai001 = rows.find((r) => r.id === 'AAI001')!;
    const aai012 = rows.find((r) => r.id === 'AAI012')!;
    expect(aai001.checks).toContain('CC-001');
    expect(aai001.failed).toBe(1);
    expect(aai012.checks).toContain('CC-001');
    expect(aai012.failed).toBe(1);

    const aai003 = rows.find((r) => r.id === 'AAI003')!;
    expect(aai003.checks).toEqual(['MCP-024']);
    expect(aai003.failed).toBe(0);
    expect(aai003.covered).toBe(true);
  });

  it('renders AAI014 (alignment faking) as an uncovered gap', () => {
    const rows = computeOwaspAgenticCoverage(resultWith([{ id: 'CC-001', passed: false }]));
    expect(rows.find((r) => r.id === 'AAI014')!.covered).toBe(false);
  });

  it('always returns all ten risks', () => {
    expect(computeOwaspAgenticCoverage(resultWith([])).length).toBe(10);
  });
});

describe('rendering', () => {
  it('renders a coverage table when Agentic findings exist', () => {
    const result = resultWith([{ id: 'CC-001', passed: false }]);
    expect(hasOwaspAgenticFindings(result)).toBe(true);
    const md = renderOwaspAgenticCoverageMarkdown(result);
    expect(md).toContain('OWASP Agentic AI Top 10 Coverage');
    expect(md).toContain('AAI001');
    expect(md).toContain('AAI014'); // gap row still rendered
  });

  it('renders nothing when there are no Agentic findings', () => {
    const result = resultWith([{ id: 'CG-001', passed: false }]);
    expect(hasOwaspAgenticFindings(result)).toBe(false);
    expect(renderOwaspAgenticCoverageMarkdown(result)).toBe('');
  });
});

describe('map integrity (drift guard)', () => {
  registerAllChecks();
  const realIds = new Set(checkRegistry.getAll().map((c) => c.id));
  const validRisks = new Set(Object.keys(OWASP_AGENTIC_TITLES));

  it('maps only real, registered check IDs', () => {
    const stale = Object.keys(CHECK_AGENTIC_MAP).filter((id) => !realIds.has(id));
    expect(stale).toEqual([]);
  });

  it('uses only valid AAI risk IDs and never assigns AAI014', () => {
    for (const [id, risks] of Object.entries(CHECK_AGENTIC_MAP)) {
      expect(risks.length, `${id} has no tags`).toBeGreaterThan(0);
      for (const r of risks) {
        expect(validRisks.has(r), `${id} -> invalid ${r}`).toBe(true);
        expect(r, `${id} should not map to AAI014`).not.toBe('AAI014');
      }
    }
  });

  it('tags every mapped check in the live registry via applyAgenticTags', () => {
    const tagged = checkRegistry.getAll().filter((c) => c.owaspAgentic && c.owaspAgentic.length > 0);
    expect(tagged.length).toBe(Object.keys(CHECK_AGENTIC_MAP).length);
  });
});
