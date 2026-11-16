import { describe, expect, it } from 'vitest';
import type { AgentInventory, CheckResult } from '../core/types.js';
import { linkInventoryFindings } from './findings.js';

const fail = (id: string, file: string, snippet?: string): CheckResult => ({
  id, name: id, category: 'skills', severity: 'warning', passed: false, message: 'm', evidence: [{ file, ...(snippet ? { snippet } : {}) }],
});

describe('linkInventoryFindings', () => {
  it('links failed checks to the skill holding the evidence, also through its symlink target', () => {
    const inv: AgentInventory = {
      skillsDirs: [],
      skills: [
        { name: 'a', path: '/s/a', root: '/s', scope: 'user', kind: 'skill-md', files: 2, hasCode: true },
        { name: 'b', path: '/s/b', root: '/s', scope: 'user', kind: 'skill-md', files: 1, hasCode: false, symlinkTarget: '/s/pack/b' },
        { name: 'ab', path: '/s/ab', root: '/s', scope: 'user', kind: 'skill-md', files: 1, hasCode: false },
      ],
      otherEntries: [],
    };
    linkInventoryFindings(inv, [
      fail('SKL-001', '/s/a/run.js'),
      fail('SKL-003', '/s/a/x.py'),
      fail('SKL-003', '/s/a/y.py'),
      fail('SKL-002', '/s/pack/b/tool.sh'),
      { ...fail('SKL-009', '/s/a/z.js'), passed: true },
    ]);
    expect(inv.skills.map(s => s.findings)).toEqual([['SKL-001', 'SKL-003'], ['SKL-002'], undefined]);
  });

  it('links MCP findings only where a check names the server, in its scope', () => {
    const server = (name: string, extra: Partial<NonNullable<AgentInventory['mcpServers']>[number]> = {}) =>
      ({ name, configFile: '/h/.claude.json', scope: 'user' as const, transport: 'stdio' as const, ...extra });
    const inv: AgentInventory = {
      skillsDirs: [], skills: [], otherEntries: [],
      mcpServers: [
        server('pg'), server('db'), server('github'), server('api'), server('api.v2'),
        server('github', { scope: 'project', project: '/work/app' }),
        server('off', { disabled: true }),
        server('npx'), server('risk'),
      ],
    };
    linkInventoryFindings(inv, [
      fail('CC-005', '/h/.claude.json', 'mcpServers.pg: npx -y pg-mcp --conn db'),
      fail('CC-005', '/h/.claude.json', 'mcpServers.foo: npx -y @acme/github'),
      fail('CC-004', '/h/.claude.json', 'projects[/work/app].mcpServers.github.env.GITHUB_TOKEN = ***'),
      fail('CUR-006', '/h/.claude.json', 'mcpServers.api.v2.url = http://x'),
      fail('DEV-004', '/h/.claude.json', 'mcpServers.off: npx -y thing'),
      { ...fail('CD-003', '/h/.claude.json', 'x'), evidence: [{ file: '/h/.claude.json', snippet: 'x', detail: 'MCP server package unpinned — supply chain risk' }] },
      fail('GEM-008', '/other.json', 'mcpServers.pg.url = http://x'),
    ]);
    const by = Object.fromEntries(inv.mcpServers!.map(s => [`${s.name}${s.project ? '@' + s.project : ''}`, s.findings]));
    expect(by).toEqual({
      pg: ['CC-005'], db: undefined, github: undefined, api: undefined, 'api.v2': ['CUR-006'],
      'github@/work/app': ['CC-004'], off: undefined, npx: undefined, risk: undefined,
    });
  });

  it('links project-scope servers declared in the project\'s own file without a projects[] prefix', () => {
    const inv: AgentInventory = {
      skillsDirs: [], skills: [], otherEntries: [],
      mcpServers: [
        { name: 'p', configFile: '/work/app/.mcp.json', scope: 'project', project: '/work/app', transport: 'stdio' },
        { name: 'c', configFile: '/work/app/.cursor/mcp.json', scope: 'project', project: '/work/app', transport: 'stdio' },
      ],
    };
    linkInventoryFindings(inv, [
      fail('CC-005', '/work/app/.mcp.json', 'mcpServers.p: npx -y thing'),
      fail('CUR-006', '/work/app/.cursor/mcp.json', 'mcpServers.c.url = http://x'),
    ]);
    expect(inv.mcpServers!.map(s => s.findings)).toEqual([['CC-005'], ['CUR-006']]);
  });

  it("links Abacus.AI's array form by name", () => {
    const inv: AgentInventory = {
      skillsDirs: [], skills: [], otherEntries: [],
      mcpServers: [{ name: 'db', configFile: '/a.json', scope: 'user', transport: 'stdio' }],
    };
    linkInventoryFindings(inv, [fail('ABA-004', '/a.json', 'mcpServers[db].env.DB_PASSWORD: ***')]);
    expect(inv.mcpServers![0].findings).toEqual(['ABA-004']);
  });

  it('links other entries by path', () => {
    const inv: AgentInventory = {
      skillsDirs: [], skills: [],
      otherEntries: [{ path: '/s/sshdir', root: '/s', type: 'directory', files: 0, hasCode: false }],
    };
    linkInventoryFindings(inv, [fail('SKL-013', '/s/sshdir')]);
    expect(inv.otherEntries[0].findings).toEqual(['SKL-013']);
  });

  it('links tens of thousands of entries against as many evidence items in linear time', () => {
    const n = 20000;
    const inv: AgentInventory = {
      skillsDirs: [], skills: [],
      otherEntries: Array.from({ length: n }, (_, i) => ({ path: `/h/skills/l${i}`, root: '/h/skills', type: 'directory' as const, files: 0, hasCode: false })),
    };
    const results = [
      { ...fail('SKL-002', '/h/skills/l0'), evidence: Array.from({ length: n }, (_, i) => ({ file: `/h/skills/l${i}` })) },
      { ...fail('SKL-013', '/h/skills/l7/x'), evidence: [{ file: '/h/skills/l7/x' }, { file: '/h/skills/l7' }] },
      fail('SKL-004', '/elsewhere/a.sh'),
    ] as CheckResult[];
    const t0 = Date.now();
    linkInventoryFindings(inv, results);
    expect(Date.now() - t0).toBeLessThan(5000);
    expect(inv.otherEntries[7].findings).toEqual(['SKL-002', 'SKL-013']);
    // l1 is no folder of l10–l19's evidence
    expect(inv.otherEntries[1].findings).toEqual(['SKL-002']);
  });
});
