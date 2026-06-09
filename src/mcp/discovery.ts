import { join } from 'node:path';
import type { MCPConfig, MCPServerEntry, MCPDiscoveryResult } from './types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';

interface ConfigLocation {
  source: string;
  path: string;
}

function getGlobalConfigLocations(platform: NodeJS.Platform, home: string): ConfigLocation[] {
  const locations: ConfigLocation[] = [];

  // Claude Desktop
  if (platform === 'darwin') {
    locations.push({
      source: 'Claude Desktop',
      path: join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
    });
  } else if (platform === 'linux') {
    locations.push({
      source: 'Claude Desktop',
      path: join(home, '.config', 'Claude', 'claude_desktop_config.json'),
    });
  } else if (platform === 'win32') {
    const appData = process.env.APPDATA ?? join(home, 'AppData', 'Roaming');
    locations.push({
      source: 'Claude Desktop',
      path: join(appData, 'Claude', 'claude_desktop_config.json'),
    });
  }

  // Claude Code
  locations.push({
    source: 'Claude Code',
    path: join(home, '.claude', 'mcp.json'),
  });

  // Cursor
  locations.push({
    source: 'Cursor',
    path: join(home, '.cursor', 'mcp.json'),
  });

  // Windsurf
  locations.push({
    source: 'Windsurf',
    path: join(home, '.codeium', 'windsurf', 'mcp_config.json'),
  });

  return locations;
}

function getProjectConfigLocations(projectDir: string): ConfigLocation[] {
  return [
    { source: 'Claude Code (project)', path: join(projectDir, '.mcp.json') },
    { source: 'Cursor (project)', path: join(projectDir, '.cursor', 'mcp.json') },
    { source: 'Windsurf (project)', path: join(projectDir, '.windsurf', 'mcp.json') },
    { source: 'VS Code', path: join(projectDir, '.vscode', 'mcp.json') },
    { source: 'Generic MCP', path: join(projectDir, 'mcp.json') },
  ];
}

function parseServerEntries(data: Record<string, unknown>): MCPServerEntry[] {
  const servers: MCPServerEntry[] = [];
  const mcpServers = data.mcpServers as Record<string, Record<string, unknown>> | undefined;
  if (!mcpServers || typeof mcpServers !== 'object') return servers;

  for (const [name, config] of Object.entries(mcpServers)) {
    if (!config || typeof config !== 'object') continue;

    let transport: MCPServerEntry['transport'] = 'stdio';
    if (config.url) {
      const url = String(config.url);
      if (url.includes('/sse')) {
        transport = 'sse';
      } else {
        transport = 'streamable-http';
      }
    }

    servers.push({
      name,
      command: config.command ? String(config.command) : undefined,
      args: Array.isArray(config.args) ? config.args.map(String) : undefined,
      env: config.env && typeof config.env === 'object'
        ? Object.fromEntries(Object.entries(config.env as Record<string, unknown>).map(([k, v]) => [k, String(v)]))
        : undefined,
      headers: config.headers && typeof config.headers === 'object'
        ? Object.fromEntries(Object.entries(config.headers as Record<string, unknown>).map(([k, v]) => [k, String(v)]))
        : undefined,
      url: config.url ? String(config.url) : undefined,
      transport,
    });
  }

  return servers;
}

export class MCPDiscovery {
  private fs: FSProvider;

  constructor(fs?: FSProvider) {
    this.fs = fs ?? new LocalFSProvider();
  }

  async discover(
    platform: NodeJS.Platform = process.platform,
    projectDir?: string,
  ): Promise<MCPDiscoveryResult> {
    const configs: MCPConfig[] = [];
    const home = this.fs.homedir();

    const locations = [
      ...getGlobalConfigLocations(platform, home),
      ...(projectDir ? getProjectConfigLocations(projectDir) : []),
    ];

    for (const location of locations) {
      if (!await this.fs.access(location.path)) continue;

      try {
        const raw = await this.fs.readFile(location.path);
        const data = JSON.parse(raw) as Record<string, unknown>;
        const servers = parseServerEntries(data);

        if (servers.length > 0) {
          configs.push({
            source: location.source,
            filePath: location.path,
            servers,
          });
        }
      } catch {
        // Skip unparseable configs
      }
    }

    const totalServers = configs.reduce((sum, c) => sum + c.servers.length, 0);
    return { configs, totalServers };
  }

  async discoverFromPaths(paths: string[]): Promise<MCPDiscoveryResult> {
    const configs: MCPConfig[] = [];

    for (const filePath of paths) {
      if (!await this.fs.access(filePath)) continue;

      try {
        const raw = await this.fs.readFile(filePath);
        const data = JSON.parse(raw) as Record<string, unknown>;
        const servers = parseServerEntries(data);

        if (servers.length > 0) {
          configs.push({
            source: 'Custom',
            filePath,
            servers,
          });
        }
      } catch {
        // Skip unparseable configs
      }
    }

    const totalServers = configs.reduce((sum, c) => sum + c.servers.length, 0);
    return { configs, totalServers };
  }
}
