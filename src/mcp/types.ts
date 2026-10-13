import type { ServerDependency } from './server-dependencies.js';

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
  /** Explicitly given paths (discoverFromPaths) that are missing or not valid JSON/JSONC. */
  unreadable?: string[];
}

export interface MCPServerSource {
  serverName: string;
  packageName?: string;
  localPath?: string;
  sourceCode?: string;
  /**
   * Language of `sourceCode`. Python servers (`python3 server.py`, `uv run
   * server.py`) skip the Babel-based analyzers and get the Python sink analyzer
   * instead; absent means JavaScript/TypeScript.
   */
  language?: 'javascript' | 'python';
  /**
   * Text files the server reads at runtime — named in its source and present
   * next to its entry file (a `documents/` folder of RAG content, prompt
   * files). Returned to the model as tool output, so MCP-034 reads them too.
   */
  dataFiles?: MCPDataFile[];
  /** Packages the server ships with (its manifest/lockfile/installed copies), for MCP-027. */
  dependencies?: ServerDependency[];
  /**
   * Directory the `// === <file> ===` markers in a multi-file `sourceCode`
   * are relative to — evidence lines in the joined text are mapped back to
   * `<sourceRoot>/<file>` (see mapSourceEvidence).
   */
  sourceRoot?: string;
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

export interface MCPDataFile {
  path: string;
  content: string;
}
