/**
 * Name normalization for MCP server packages and config keys, used by the
 * provenance check (MCP-008) to compare like with like.
 */

/**
 * The package name in an install spec, without version or extras:
 * `@scope/pkg@1.2.3` → `@scope/pkg`, `pkg@latest` → `pkg`,
 * `mcp-server-git==0.6.2` → `mcp-server-git`, `pkg[cli]>=1` → `pkg`.
 */
export function bareName(spec: string): string {
  let name = spec.trim();
  const at = name.lastIndexOf('@');
  if (at > 0) name = name.slice(0, at);
  return name.replace(/\[.*$/, '').replace(/\s*(?:===?|~=|!=|>=?|<=?).*$/, '');
}

/** Name parts that say "this is an MCP server" rather than which service it is. */
const GENERIC_PARTS = new Set([
  'mcp', 'mcps', 'server', 'servers', 'modelcontextprotocol', 'model', 'context', 'protocol',
  'official', 'tool', 'tools', 'plugin', 'integration', 'connector', 'api', 'ai', 'node', 'js', 'py', 'python',
]);

/**
 * The service a package or server key is named for, with scope, version and
 * MCP boilerplate removed: `twittter-mcp` → `twittter`,
 * `@modelcontextprotocol/server-github@1.0.0` → `github`,
 * `mcp-server-brave-search` → `bravesearch`. Empty when nothing specific is left.
 */
export function serviceCore(name: string): string {
  const unscoped = bareName(name).toLowerCase().replace(/^@[^/]+\//, '');
  return unscoped
    .split(/[-_./\s]+/)
    .filter((part) => part && !GENERIC_PARTS.has(part))
    .join('');
}
