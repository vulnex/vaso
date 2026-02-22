import { createRequire } from 'node:module';
import { writeFile, mkdir } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';

const PROJECT_ROOT = resolve(import.meta.dirname, '../../..');
const require = createRequire(join(PROJECT_ROOT, 'package.json'));

interface MCPServerEntry {
  command?: string;
  args?: string[];
  url?: string;
  env?: Record<string, string>;
}

interface MCPConfig {
  mcpServers: Record<string, MCPServerEntry>;
}

/**
 * Resolve the main/bin entry point for an installed MCP server package.
 * Falls back to require.resolve if bin is not found.
 */
function resolvePackageBin(packageName: string): string {
  try {
    // Try to resolve the package's main entry point
    return require.resolve(packageName);
  } catch {
    // If the package isn't installed, return a placeholder
    // Tests should skip or handle this case
    return packageName;
  }
}

export interface GenerateMCPConfigOptions {
  /** Include insecure entries (risky-server with plaintext keys, insecure-sse) */
  includeInsecure?: boolean;
  /** Include vulnerable server source path for MCP-004/005/006 */
  vulnerableServerPath?: string;
}

/**
 * Generate an MCP config pointing to real installed MCP server packages.
 * Returns the config object and the path where it was written.
 */
export async function generateMCPConfig(
  outputPath: string,
  options: GenerateMCPConfigOptions = {},
): Promise<MCPConfig> {
  const servers: Record<string, MCPServerEntry> = {};

  // Real MCP server packages — resolved to actual installed paths
  const packages: Record<string, { pkg: string; extraArgs?: string[] }> = {
    filesystem: {
      pkg: '@modelcontextprotocol/server-filesystem',
      extraArgs: ['/tmp'],
    },
    memory: {
      pkg: '@modelcontextprotocol/server-memory',
    },
    everything: {
      pkg: '@modelcontextprotocol/server-everything',
    },
    'sequential-thinking': {
      pkg: '@modelcontextprotocol/server-sequential-thinking',
    },
  };

  for (const [name, { pkg, extraArgs }] of Object.entries(packages)) {
    const binPath = resolvePackageBin(pkg);
    servers[name] = {
      command: 'node',
      args: [binPath, ...(extraArgs ?? [])],
    };
  }

  // Insecure entries to trigger MCP-002, MCP-003
  if (options.includeInsecure) {
    servers['risky-server'] = {
      command: 'npx',
      args: ['-y', 'mcp-server-risky'],
      env: {
        OPENAI_API_KEY: 'sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx',
        AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        DATABASE_PASSWORD: 'super_secret_password_12345',
      },
    };

    servers['insecure-sse'] = {
      url: 'http://0.0.0.0:8080/sse',
    };
  }

  // Vulnerable server source for MCP-004/005/006
  if (options.vulnerableServerPath) {
    servers['admin-server'] = {
      command: 'node',
      args: [options.vulnerableServerPath, '--host', '0.0.0.0'],
    };
  }

  const config: MCPConfig = { mcpServers: servers };

  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, JSON.stringify(config, null, 2));

  return config;
}
