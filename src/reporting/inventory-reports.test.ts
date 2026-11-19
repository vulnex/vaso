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

  it('terminal: a refused or uncollected skills directory is "not scanned", not "0 skills"', () => {
    const r = result();
    const inv = r.agents[0].installation.inventory!;
    inv.skillsDirs = [{ path: '/opt/team/skills', exists: true, unverified: true }];
    inv.skills = [];
    inv.otherEntries = [];
    inv.incomplete = ['/opt/team/skills: outside the home — not scanned'];
    expect(getReporter('terminal').render(r)).toContain('Surface: skills not scanned, 2 MCP servers');
    inv.skillsDirs.push({ path: '/home/u/.claude/skills', exists: true });
    expect(getReporter('terminal').render(r)).toContain('Surface: 0 skills (skills inventory incomplete), 2 MCP servers');
  });
});

describe('inventory in reports — links, profiles, host notes', () => {
  const failed = (id: string) => ({ id, name: 'n', category: 'coding-agent', severity: 'warning', passed: false, message: 'm' }) as ScanResult['agents'][number]['results'][number];

  it('HTML: inventory finding ids link to their row; ids from rules are made safe', () => {
    const r = result();
    const evil = 'ORG-1"><script>alert(1)</script>';
    r.agents[0].results = [failed('CC-005'), failed('CONFIG-LOAD'), failed('CONFIG-LOAD'), failed(evil)];
    r.agents[0].installation.inventory!.mcpServers![0].findings = ['CC-005', evil];
    const html = getReporter('html').render(r);
    expect(html).toContain('<tr id="finding-0-CC-005">');
    expect(html).toContain('<a href="#finding-0-CC-005">CC-005</a>');
    // a finding id with no row of its own (SKL-001 passed here) stays text
    expect(html).toContain('<td>SKL-001</td>');
    // one anchor per id
    expect(html.match(/id="finding-0-CONFIG-LOAD"/g)).toHaveLength(1);
    expect(html).not.toContain('<script>');
    const id = /<tr id="(finding-0-ORG-1[^"]*)">/.exec(html)?.[1];
    expect(id).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(html).toContain(`<a href="#${id}">ORG-1&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;</a>`);
    // .muted styles the Host section too, not only the collapsed surface
    expect(html).toMatch(/\n {2}\.muted \{/);
  });

  it('names a shared server\'s profile and project, and the host notes, in every format', () => {
    const r = result();
    r.hostInventory!.sharedMcpServers![0].users = [
      { agent: 'openclaw', installDir: '/home/u/.openclaw', server: 's', configFile: '/home/u/.openclaw/openclaw.json', pin: 'none' },
      { agent: 'openclaw', profile: 'work', installDir: '/home/u/.openclaw-work', server: 's', configFile: '/home/u/.openclaw-work/openclaw.json', pin: 'none' },
      { agent: 'claude-code', installDir: '/home/u/.claude', server: 'x', project: '/srv/app', configFile: '/home/u/.claude.json', pin: 'none' },
    ];
    r.hostInventory!.incomplete = ['/home/u/.config/Code/User/settings.json: VS Code settings are not collected by the remote probe'];
    const html = getReporter('html').render(r);
    expect(html).toContain('openclaw (profile work): s');
    expect(html).toContain('claude-code: x (project /srv/app)');
    expect(html).toContain('! /home/u/.config/Code/User/settings.json: VS Code settings are not collected');
    const md = getReporter('markdown').render(r);
    expect(md).toContain('openclaw: s, openclaw (profile work): s, claude-code: x (project /srv/app)');
    expect(md).toContain('VS Code settings are not collected');
    expect(getReporter('terminal').render(r)).toContain('VS Code settings are not collected');
    const sarif = JSON.parse(getReporter('sarif').render(r));
    expect(sarif.runs[0].properties.inventory.host.incomplete).toHaveLength(1);
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
