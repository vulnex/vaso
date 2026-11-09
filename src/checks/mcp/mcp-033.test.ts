import { describe, it, expect } from 'vitest';
import type { ScanContext } from '../../core/types.js';
import type { MCPConfig } from '../../mcp/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { mcp033 } from './mcp-033-long-lived-token.js';

function ctx(env: Record<string, string>): ScanContext {
  const mcpConfigs: MCPConfig[] = [{ source: 'test', filePath: '/tmp/mcp.json', servers: [{ name: 's', command: 'node', args: ['s.js'], env, transport: 'stdio' }] }];
  return {
    installation: { agent: 'mcp', installDir: '/tmp', configFiles: [] },
    configs: [], platform: 'linux', fs: new LocalFSProvider(), mcpConfigs,
  };
}

// g3-F6: placeholders and references are no stored token
describe('MCP-033 placeholders and references', () => {
  it.each([
    '<YOUR_SLACK_TOKEN>', 'xoxb-xxxxxxxxxxxx', 'op://vault/slack/token', '${env:SLACK_TOKEN}',
    '${input:slack_token}', '${SLACK_TOKEN:-}', '${SLACK_TOKEN}', '$SLACK_TOKEN', 'your-token-here',
  ])('does not report %s', async (value) => {
    expect((await mcp033.run(ctx({ SLACK_BOT_TOKEN: value }))).passed).toBe(true);
  });

  it('still reports a literal static token without refresh/expiry', async () => {
    const r = await mcp033.run(ctx({ SLACK_BOT_TOKEN: 'xoxb-2847561938-5823917465-q8Z2x7Lk3Vm9Np4Rt6Wy1Bc5' }));
    expect(r.passed).toBe(false);
  });
});
