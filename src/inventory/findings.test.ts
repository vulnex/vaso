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
      ({ name, configFile: '/c.json', scope: 'user' as const, transport: 'stdio' as const, ...extra });
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
      fail('CC-005', '/c.json', 'mcpServers.pg: npx -y pg-mcp --conn db'),
      fail('CC-005', '/c.json', 'mcpServers.foo: npx -y @acme/github'),
      fail('CC-004', '/c.json', 'projects[/work/app].mcpServers.github.env.GITHUB_TOKEN = ***'),
      fail('CUR-006', '/c.json', 'mcpServers.api.v2.url = http://x'),
      fail('DEV-004', '/c.json', 'mcpServers.off: npx -y thing'),
      { ...fail('CD-003', '/c.json', 'x'), evidence: [{ file: '/c.json', snippet: 'x', detail: 'MCP server package unpinned — supply chain risk' }] },
      fail('GEM-008', '/other.json', 'mcpServers.pg.url = http://x'),
    ]);
    const by = Object.fromEntries(inv.mcpServers!.map(s => [`${s.name}${s.project ? '@' + s.project : ''}`, s.findings]));
    expect(by).toEqual({
      pg: ['CC-005'], db: undefined, github: undefined, api: undefined, 'api.v2': ['CUR-006'],
      'github@/work/app': ['CC-004'], off: undefined, npx: undefined, risk: undefined,
    });
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
});
