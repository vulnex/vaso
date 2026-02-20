import { describe, it, expect } from 'vitest';
import { MCPDiscovery } from './discovery.js';
import { join } from 'node:path';

const FIXTURES = join(__dirname, '../../testing/fixtures/mcp');

describe('MCPDiscovery', () => {
  it('discovers servers from insecure fixture config', async () => {
    const discovery = new MCPDiscovery();
    const result = await discovery.discoverFromPaths([
      join(FIXTURES, 'insecure/claude_desktop_config.json'),
    ]);

    console.log(`[MCPDiscovery] insecure → configs: ${result.configs.length}, servers: ${result.totalServers}`);

    expect(result.configs).toHaveLength(1);
    expect(result.totalServers).toBe(4);

    const servers = result.configs[0].servers;
    expect(servers.map(s => s.name)).toContain('risky-server');
    expect(servers.map(s => s.name)).toContain('insecure-sse');
    expect(servers.map(s => s.name)).toContain('admin-server');
    expect(servers.map(s => s.name)).toContain('typo-filesystam');
  });

  it('discovers servers from secure fixture config', async () => {
    const discovery = new MCPDiscovery();
    const result = await discovery.discoverFromPaths([
      join(FIXTURES, 'secure/claude_desktop_config.json'),
    ]);

    console.log(`[MCPDiscovery] secure → configs: ${result.configs.length}, servers: ${result.totalServers}`);

    expect(result.configs).toHaveLength(1);
    expect(result.totalServers).toBe(3);

    const servers = result.configs[0].servers;
    expect(servers.find(s => s.name === 'filesystem')?.transport).toBe('stdio');
    expect(servers.find(s => s.name === 'secure-sse')?.transport).toBe('sse');
  });

  it('parses transport types correctly', async () => {
    const discovery = new MCPDiscovery();
    const result = await discovery.discoverFromPaths([
      join(FIXTURES, 'insecure/claude_desktop_config.json'),
    ]);

    const servers = result.configs[0].servers;
    const sseServer = servers.find(s => s.name === 'insecure-sse');
    const stdioServer = servers.find(s => s.name === 'risky-server');

    console.log(`[MCPDiscovery] sse transport: ${sseServer?.transport}, stdio transport: ${stdioServer?.transport}`);

    expect(sseServer?.transport).toBe('sse');
    expect(stdioServer?.transport).toBe('stdio');
  });

  it('parses env blocks correctly', async () => {
    const discovery = new MCPDiscovery();
    const result = await discovery.discoverFromPaths([
      join(FIXTURES, 'insecure/claude_desktop_config.json'),
    ]);

    const risky = result.configs[0].servers.find(s => s.name === 'risky-server');

    console.log(`[MCPDiscovery] env keys: ${Object.keys(risky?.env ?? {}).join(', ')}`);

    expect(risky?.env).toBeDefined();
    expect(risky?.env?.OPENAI_API_KEY).toContain('sk-proj-');
    expect(risky?.env?.AWS_SECRET_ACCESS_KEY).toBeDefined();
    expect(risky?.env?.DATABASE_PASSWORD).toBeDefined();
  });

  it('returns empty result for non-existent paths', async () => {
    const discovery = new MCPDiscovery();
    const result = await discovery.discoverFromPaths([
      '/non/existent/path.json',
    ]);

    console.log(`[MCPDiscovery] non-existent → configs: ${result.configs.length}`);

    expect(result.configs).toHaveLength(0);
    expect(result.totalServers).toBe(0);
  });

  it('handles multiple config files', async () => {
    const discovery = new MCPDiscovery();
    const result = await discovery.discoverFromPaths([
      join(FIXTURES, 'insecure/claude_desktop_config.json'),
      join(FIXTURES, 'secure/claude_desktop_config.json'),
    ]);

    console.log(`[MCPDiscovery] multiple → configs: ${result.configs.length}, servers: ${result.totalServers}`);

    expect(result.configs).toHaveLength(2);
    expect(result.totalServers).toBe(7);
  });
});
