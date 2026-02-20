export interface MCPServerEntry {
  name: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  transport: 'stdio' | 'sse' | 'streamable-http';
}

export interface MCPConfig {
  source: string;
  filePath: string;
  servers: MCPServerEntry[];
}

export interface MCPDiscoveryResult {
  configs: MCPConfig[];
  totalServers: number;
}

export interface MCPServerSource {
  serverName: string;
  packageName?: string;
  localPath?: string;
  sourceCode?: string;
}
