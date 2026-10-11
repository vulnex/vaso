import { describe, it, expect } from 'vitest';
import { remoteEndpoint } from './remote-endpoint.js';
import type { MCPServerEntry } from './types.js';

function server(overrides: Partial<MCPServerEntry>): MCPServerEntry {
  return { name: 's', transport: 'stdio', ...overrides };
}

describe('remoteEndpoint', () => {
  it('returns a direct url entry as-is', () => {
    expect(remoteEndpoint(server({ url: 'https://mcp.example.com/sse', transport: 'sse' }))).toEqual({
      url: 'https://mcp.example.com/sse',
      transport: 'sse',
    });
  });

  it('returns undefined for a plain stdio server', () => {
    expect(remoteEndpoint(server({ command: 'node', args: ['/srv/index.js'] }))).toBeUndefined();
    expect(remoteEndpoint(server({ command: 'npx', args: ['-y', '@modelcontextprotocol/server-memory'] }))).toBeUndefined();
  });

  it('reads the URL from npx mcp-remote (pinned or not)', () => {
    for (const pkg of ['mcp-remote', 'mcp-remote@0.1.15']) {
      const ep = remoteEndpoint(server({ command: 'npx', args: ['-y', pkg, 'https://mcp.example.com/mcp'] }));
      expect(ep).toMatchObject({
        url: 'https://mcp.example.com/mcp',
        transport: 'streamable-http',
        via: 'mcp-remote',
        allowHttp: false,
        negotiatesOAuth: true,
      });
    }
  });

  it('records mcp-remote --allow-http and an SSE transport strategy', () => {
    const ep = remoteEndpoint(server({
      command: 'npx',
      args: ['mcp-remote', 'http://agents.example.com/sse', '9696', '--allow-http', '--transport', 'sse-only'],
    }));
    expect(ep).toMatchObject({ url: 'http://agents.example.com/sse', transport: 'sse', allowHttp: true });
  });

  it('recognizes a globally installed mcp-remote and bunx', () => {
    expect(remoteEndpoint(server({ command: '/usr/local/bin/mcp-remote', args: ['https://a.example.com/mcp'] }))?.via)
      .toBe('mcp-remote');
    expect(remoteEndpoint(server({ command: 'bunx', args: ['mcp-remote', 'https://a.example.com/mcp'] }))?.via)
      .toBe('mcp-remote');
  });

  it('reads supergateway --sse and --streamableHttp (both flag forms)', () => {
    expect(remoteEndpoint(server({ command: 'npx', args: ['-y', 'supergateway', '--sse', 'https://a.example.com/sse'] })))
      .toMatchObject({ url: 'https://a.example.com/sse', transport: 'sse', via: 'supergateway' });
    expect(remoteEndpoint(server({ command: 'npx', args: ['supergateway', '--streamableHttp=https://a.example.com/mcp'] })))
      .toMatchObject({ url: 'https://a.example.com/mcp', transport: 'streamable-http', via: 'supergateway' });
    expect(remoteEndpoint(server({ command: 'npx', args: ['supergateway', '--sse', 'https://a.example.com/sse'] }))?.negotiatesOAuth)
      .toBeUndefined();
  });

  it('ignores supergateway serving a local stdio server', () => {
    expect(remoteEndpoint(server({ command: 'npx', args: ['-y', 'supergateway', '--stdio', 'node server.js', '--port', '8000'] })))
      .toBeUndefined();
  });

  it('ignores a bridge with no URL', () => {
    expect(remoteEndpoint(server({ command: 'npx', args: ['-y', 'mcp-remote', '--help'] }))).toBeUndefined();
  });
});
