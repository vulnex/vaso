import type { ServerDependency } from './server-dependencies.js';
import type { PackageFetchFailure } from './package-fetcher.js';

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

/** Where a config applies: the user's, one project's, or an extension's. */
export type MCPConfigScope = 'user' | 'project' | 'extension';

export interface MCPConfig {
  source: string;
  filePath: string;
  servers: MCPServerEntry[];
  /** The agents that load this file (discover() only); empty when no detected
   *  agent owns it (VS Code, a bare project mcp.json). */
  agents?: import('../core/types.js').AgentType[];
  /** Absent means user scope. */
  scope?: MCPConfigScope;
  /** The project the config applies to (project scope). */
  projectRoot?: string;
}

export interface MCPDiscoveryResult {
  configs: MCPConfig[];
  totalServers: number;
  /** Explicitly given paths (discoverFromPaths) that are missing or not valid JSON/JSONC. */
  unreadable?: string[];
  /** Explicitly given paths that parsed but hold no MCP servers in any known dialect. */
  empty?: string[];
  /** Discovered config files (discover) that exist but could not be read or parsed. */
  loadErrors?: MCPConfigLoadError[];
}

export interface MCPConfigLoadError {
  /** The client the file belongs to ("Cursor", "Claude Code", …). */
  source: string;
  filePath: string;
  stage: 'read' | 'parse';
  message: string;
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
  /** `--resolve-packages`: why the package's source could not be downloaded (no source then). */
  resolveFailure?: PackageFetchFailure;
  /**
   * A local server whose source is there but could not be read (EACCES, the
   * size limits): why. With `sourceCode`, part of it — helper modules — was
   * not read.
   */
  readFailure?: string;
  /**
   * The local server is a compiled binary (a Go/Rust executable): its format.
   * No source then — reported as an inventory note, not a failed read.
   */
  compiledBinary?: string;
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
