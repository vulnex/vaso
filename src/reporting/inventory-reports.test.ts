import { describe, expect, it } from 'vitest';
import type { ScanResult } from '../core/types.js';
import { getReporter } from './index.js';

function result(): ScanResult {
  return {
    timestamp: '2026-11-13T00:00:00.000Z',
    agents: [{
      agent: 'claude-code',
      installation: {
        agent: 'claude-code',
        installDir: '/home/u/.claude',
        configFiles: [],
        inventory: {
          skillsDirs: [{ path: '/home/u/.claude/skills', exists: true }, { path: '/gone', exists: false }],
          skills: [{
            name: '<img src=x onerror=alert(1)>', path: '/home/u/.claude/skills/evil', root: '/home/u/.claude/skills',
            scope: 'user', kind: 'skill-md', description: 'pipes | and\nnewlines', files: 2, hasCode: true, findings: ['SKL-001'],
          }],
          otherEntries: [{ path: '/home/u/.claude/skills/loose', root: '/home/u/.claude/skills', type: 'directory', files: 1, hasCode: true }],
          mcpServers: [{
            name: 'github', configFile: '/home/u/.claude.json', scope: 'user', transport: 'stdio', command: 'npx',
            args: ['-y', '@modelcontextprotocol/server-github'], envNames: ['GITHUB_TOKEN'],
            package: { runner: 'npx', ecosystem: 'npm', name: '@modelcontextprotocol/server-github', spec: '@modelcontextprotocol/server-github', pin: 'none' },
            findings: ['CC-005'],
          }, {
            name: 'remote', configFile: '/home/u/.claude.json', scope: 'project', project: '/srv/app', transport: 'streamable-http',
            url: 'https://mcp.example.com/sse?token=sk-live-abcdefghijklmnopqrstuvwx',
            disabled: true,
          }],
        },
      },
      results: [],
      score: 100,
      grade: 'A',
    }],
    totalScore: 100,
    totalGrade: 'A',
    fleetAverage: 100,
    summary: { critical: 0, warning: 0, info: 0, passed: 0, total: 0 },
    hostInventory: {
      mcpServers: [{ name: 'vscode-srv', configFile: '/home/u/.config/Code/User/mcp.json', scope: 'user', transport: 'stdio', command: 'node', args: ['s.js'] }],
      sharedMcpServers: [{
        key: 'npm:@modelcontextprotocol/server-github',
        unpinned: true,
        users: [
          { agent: 'claude-code', installDir: '/home/u/.claude', server: 'github', configFile: '/home/u/.claude.json', pin: 'none' },
          { agent: 'cursor-cli', installDir: '/home/u/.cursor', server: '<b>gh</b>', configFile: '/home/u/.cursor/mcp.json', pin: 'exact' },
        ],
      }],
    },
  };
}

describe('inventory in reports', () => {
  it('HTML: collapsible surface per agent, escaped, plus the host block', () => {
    const html = getReporter('html').render(result());
    expect(html).toContain('<summary>Attack surface: 1 skill, 1 other skills-dir entry, 2 MCP servers (1 disabled)</summary>');
    expect(html).not.toContain('<img src=x');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(html).toContain('@modelcontextprotocol/server-github (unpinned)');
    expect(html).toContain('project /srv/app');
    expect(html).toContain('GITHUB_TOKEN');
    expect(html).toContain('CC-005');
    expect(html).toContain('vscode-srv');
    expect(html).toContain('MCP servers shared by several agents');
    expect(html).toContain('&lt;b&gt;gh&lt;/b&gt;');
    expect(html).not.toContain('<b>gh</b>');
    expect(html).not.toContain('abcdefghijklmnopqrstuvwx');
  });

  it('Markdown: surface section with tables that survive pipes and newlines', () => {
    const md = getReporter('markdown').render(result());
    expect(md).toContain('### Attack surface (1 skill, 1 other skills-dir entry, 2 MCP servers (1 disabled))');
    expect(md).toContain('pipes \\| and newlines');
    expect(md).toContain('| github | stdio | @modelcontextprotocol/server-github (unpinned) |');
    expect(md).toContain('## Host');
    expect(md).toContain('| remote (disabled) |');
    expect(md).toContain('| npm:@modelcontextprotocol/server-github | yes | claude-code: github, cursor-cli: &lt;b&gt;gh&lt;/b&gt; |');
    expect(md).toContain('(not present)');
    expect(md).not.toContain('abcdefghijklmnopqrstuvwx');
    for (const line of md.split('\n').filter(l => l.startsWith('| github') || l.startsWith('| &lt;img'))) {
      expect(line.split(/(?<!\\)\|/).length).toBe(line.startsWith('| github') ? 9 : 8);
    }
  });

  it('SARIF: inventory in the run property bag', () => {
    const sarif = JSON.parse(getReporter('sarif').render(result()));
    const inv = sarif.runs[0].properties.inventory;
    expect(inv.agents[0]).toMatchObject({ agent: 'claude-code', installDir: '/home/u/.claude' });
    expect(inv.agents[0].mcpServers.map((s: { name: string }) => s.name)).toEqual(['github', 'remote']);
    expect(inv.host.mcpServers[0].name).toBe('vscode-srv');
    expect(inv.host.sharedMcpServers[0].unpinned).toBe(true);
    expect(JSON.stringify(sarif)).not.toContain('abcdefghijklmnopqrstuvwx');
  });

  it('SARIF without any inventory has no run properties', () => {
    const r = result();
    delete r.agents[0].installation.inventory;
    delete r.hostInventory;
    expect(JSON.parse(getReporter('sarif').render(r)).runs[0].properties).toBeUndefined();
  });

  it('terminal: one surface line per agent', () => {
    const out = getReporter('terminal').render(result());
    expect(out).toContain('Surface: 1 skill, 1 other skills-dir entry, 2 MCP servers (1 disabled)');
    expect(out).toContain('Shared MCP servers: 1');
  });
});

describe('markdown link syntax from scanned text', () => {
  it('escapes link and image syntax in names and descriptions', async () => {
    const { MarkdownReporter } = await import('./markdown.js');
    const r = {
      timestamp: 't', agents: [{
        agent: 'claude-code', installation: { agent: 'claude-code', installDir: '/h', configFiles: [], inventory: {
          skillsDirs: [], otherEntries: [],
          skills: [{ name: '[click](javascript:alert(1))', path: '/s', root: '/', scope: 'user', kind: 'skill-md', description: '![x](http://evil/x.png)', files: 1, hasCode: false }],
        } }, results: [], score: 100, grade: 'A',
      }], totalScore: 100, totalGrade: 'A', fleetAverage: 100, summary: { critical: 0, warning: 0, info: 0, passed: 0, total: 0 },
    } as unknown as import('../core/types.js').ScanResult;
    const md = new MarkdownReporter().render(r);
    expect(md).not.toMatch(/(?<!\\)\[click\]\(/);
    expect(md).not.toMatch(/(?<!\\)!\[x\]/);
  });
});
