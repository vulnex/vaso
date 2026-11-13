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

  it('links MCP findings by config file and the server named as a whole word', () => {
    const server = (name: string) => ({ name, configFile: '/c.json', scope: 'user' as const, transport: 'stdio' as const });
    const inv: AgentInventory = { skillsDirs: [], skills: [], otherEntries: [], mcpServers: [server('db'), server('db2'), server('web')] };
    linkInventoryFindings(inv, [
      fail('CC-005', '/c.json', 'mcpServers.db: npx -y db-mcp'),
      fail('CC-006', '/other.json', 'mcpServers.web.url = http://x'),
      fail('CC-007', '/c.json', 'db2: uvx thing'),
    ]);
    expect(inv.mcpServers!.map(s => s.findings)).toEqual([['CC-005'], ['CC-007'], undefined]);
  });
});
