import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { ghc003 } from './ghc-003-plaintext-token.js';

function ctx(data: Record<string, unknown>): ScanContext {
  const raw = JSON.stringify(data);
  const configs: ParsedConfig[] = [{ raw, format: 'json', filePath: '/home/test/.copilot/mcp-config.json', data }];
  const fs = { homedir: () => '/home/test', platform: 'linux', access: vi.fn(async () => false) } as unknown as FSProvider;
  return { installation: { agent: 'copilot-cli', installDir: '/home/test/.copilot', configFiles: configs }, configs, platform: 'linux', fs };
}

describe('GHC-003: literal credentials in Copilot MCP servers (dt24)', () => {
  const jira = 'Jk4Lm9Qw2Er7Ty5Ui3Op8As1Df6Gh0ZxCvBnMqWe';
  const gh = 'ghp_Jr5Qw8Mt2Zk7Vn4Hb9Lc3Ys6Fd1Gp0Ue2Wax';

  it('flags env, header, arg and URL literals once each, never quoting them', async () => {
    const r = await ghc003.run(ctx({ mcpServers: {
      atl: { command: 'npx', args: ['-y', 'mcp-atlassian'], env: { JIRA_API_TOKEN: jira }, headers: { Authorization: `Bearer ${jira}` } },
      gh: { command: 'npx', args: ['-y', 'srv@1.0.0', '--token', gh] },
      web: { url: 'https://mcp.example.com/mcp?api_key=sk-proj-Hk3Lq9Zm2Vx7Rt5Wb8Nc4Py1Jd6Gs0Fa' },
    } }));
    expect(r.passed).toBe(false);
    const snippets = r.evidence?.map(e => e.snippet ?? '') ?? [];
    // the ghp_ token is reported by the raw token scan, not again as an argument
    expect(snippets.filter(s => s.includes('args'))).toEqual([]);
    expect(snippets.some(s => s.startsWith('mcpServers.atl.env.JIRA_API_TOKEN='))).toBe(true);
    expect(snippets).toContain('mcpServers.atl.headers.Authorization (literal value)');
    expect(snippets.some(s => s.startsWith('mcpServers.web.url = '))).toBe(true);
    const text = JSON.stringify(r.evidence);
    for (const s of [jira.slice(0, 8), gh.slice(4, 12), 'Hk3Lq9Zm']) expect(text).not.toContain(s);
  });

  it('passes environment references', async () => {
    const r = await ghc003.run(ctx({ mcpServers: {
      atl: { command: 'npx', args: ['-y', 'mcp-atlassian@1.2.3', '--token', '${JIRA_TOKEN}'], env: { JIRA_API_TOKEN: '${JIRA_API_TOKEN}', B: '$B_TOKEN' }, headers: { Authorization: 'Bearer ${JIRA_TOKEN}' } },
    } }));
    expect(r.passed).toBe(true);
  });
});
