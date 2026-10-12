import { describe, it, expect } from 'vitest';
import { auditDependencies } from './osv-audit.js';
import type { MCPServerSource } from './types.js';

type Call = { url: string; body?: string };

function osvFetch(vulns: Record<string, unknown>, ids: (q: { package: { name: string; ecosystem: string }; version: string }) => string[]) {
  const calls: Call[] = [];
  const fetch = async (url: string, init?: { body?: string }) => {
    calls.push({ url, body: init?.body });
    if (url.endsWith('/querybatch')) {
      const { queries } = JSON.parse(init!.body!) as { queries: Array<{ package: { name: string; ecosystem: string }; version: string }> };
      return { ok: true, status: 200, json: async () => ({ results: queries.map((q) => ({ vulns: ids(q).map((id) => ({ id })) })) }) };
    }
    const id = decodeURIComponent(url.split('/').pop()!);
    return { ok: true, status: 200, json: async () => vulns[id] };
  };
  return { fetch, calls };
}

const lodashGhsa = {
  id: 'GHSA-35jh-r3h4-6jhm',
  summary: 'Command Injection in lodash',
  aliases: ['CVE-2021-23337'],
  database_specific: { severity: 'HIGH' },
  affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }],
};

function sources(): MCPServerSource[] {
  return [
    { serverName: 'a', dependencies: [
      { name: 'lodash', ecosystem: 'npm', version: '4.17.20', source: 'a/package-lock.json' },
      { name: 'zod', ecosystem: 'npm', range: '^3.0.0', source: 'a/package.json' },
    ] },
    { serverName: 'b', dependencies: [
      { name: 'lodash', ecosystem: 'npm', version: '4.17.20', source: 'b/package-lock.json' },
      { name: 'pyyaml', ecosystem: 'pypi', version: '5.3', source: 'b/uv.lock' },
    ] },
  ];
}

describe('auditDependencies', () => {
  it('sends each exact name@version once and attaches the advisories to every copy', async () => {
    const pyyaml = { id: 'PYSEC-2021-142', summary: 'PyYAML arbitrary code execution', aliases: ['CVE-2020-14343', 'GHSA-8q59-q68h-6hv4'],
      affected: [{ package: { name: 'PyYAML', ecosystem: 'PyPI' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '5.4' }] }] }] };
    const pyyamlGhsa = { ...pyyaml, id: 'GHSA-8q59-q68h-6hv4', aliases: ['CVE-2020-14343', 'PYSEC-2021-142'], database_specific: { severity: 'CRITICAL' } };
    const { fetch, calls } = osvFetch(
      { 'GHSA-35jh-r3h4-6jhm': lodashGhsa, 'PYSEC-2021-142': pyyaml, 'GHSA-8q59-q68h-6hv4': pyyamlGhsa },
      (q) => (q.package.name === 'lodash' ? ['GHSA-35jh-r3h4-6jhm'] : ['PYSEC-2021-142', 'GHSA-8q59-q68h-6hv4']),
    );
    const srcs = sources();
    const summary = await auditDependencies(srcs, { fetch });

    expect(summary).toEqual({ queried: 2, vulnerable: 2, rangeOnly: 1 });
    // Only names, ecosystems and versions leave the machine.
    const sent = JSON.parse(calls[0].body!);
    expect(sent).toEqual({ queries: [
      { package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.20' },
      { package: { name: 'pyyaml', ecosystem: 'PyPI' }, version: '5.3' },
    ] });
    for (const s of srcs) {
      const lodash = s.dependencies!.find((d) => d.name === 'lodash');
      if (lodash) expect(lodash.vulnerabilities).toEqual([{
        id: 'CVE-2021-23337', aliases: ['GHSA-35jh-r3h4-6jhm'], summary: 'Command Injection in lodash',
        severity: 'warning', fixedVersion: '4.17.21', reference: 'https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm',
      }]);
    }
    // The GHSA and PYSEC ids are one advisory; the GHSA (rated) wins.
    const yaml = srcs[1].dependencies!.find((d) => d.name === 'pyyaml')!;
    expect(yaml.vulnerabilities).toHaveLength(1);
    expect(yaml.vulnerabilities![0]).toMatchObject({ id: 'CVE-2020-14343', severity: 'critical', fixedVersion: '5.4' });
    expect(srcs[0].dependencies!.find((d) => d.name === 'zod')!.vulnerabilities).toBeUndefined();
  });

  it('reports an unreachable OSV without attaching partial results', async () => {
    const fetch = async () => ({ ok: false, status: 503, json: async () => ({}) });
    const srcs = sources();
    const summary = await auditDependencies(srcs, { fetch });
    expect(summary.error).toBe('OSV returned HTTP 503');
    expect(srcs.flatMap((s) => s.dependencies!).some((d) => d.vulnerabilities)).toBe(false);
  });

  it('sends nothing when no dependency has an exact version', async () => {
    const { fetch, calls } = osvFetch({}, () => []);
    const summary = await auditDependencies([{ serverName: 'x', dependencies: [{ name: 'zod', ecosystem: 'npm', range: '^3', source: 'p' }] }], { fetch });
    expect(summary).toEqual({ queried: 0, vulnerable: 0, rangeOnly: 1 });
    expect(calls).toHaveLength(0);
  });
});
