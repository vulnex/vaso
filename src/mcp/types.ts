export interface MCPServerEntry {
  name: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  /** HTTP headers for remote (SSE / streamable-HTTP) servers — commonly carries `Authorization`. */
  headers?: Record<string, string>;
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
  /**
   * Tool definitions extracted from `sourceCode`, populated once by the engine
   * (see `ScanEngine.scanMCP`) so tool-layer checks (MCP-020/024/025) share one
   * extraction pass instead of each re-parsing the source.
   */
  tools?: MCPToolDefinition[];
}

export interface MCPToolDefinition {
  name: string;
  description?: string;
  schema?: string;
}
