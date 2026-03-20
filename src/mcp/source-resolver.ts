import { join, dirname, resolve } from 'node:path';
import type { MCPServerEntry, MCPServerSource } from './types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';

export function inferPackageName(server: MCPServerEntry): string | undefined {
  if (!server.command || !server.args?.length) return undefined;

  const cmd = server.command;
  const args = server.args;

  // npx @scope/package or npx package
  if (cmd === 'npx' || cmd === 'npx.cmd') {
    // Skip flags like -y, --yes, -p, --package
    for (const arg of args) {
      if (arg.startsWith('-')) continue;
      return arg;
    }
  }

  // uvx package
  if (cmd === 'uvx' || cmd === 'uv') {
    for (const arg of args) {
      if (arg === 'run' || arg === 'tool' || arg.startsWith('-')) continue;
      return arg;
    }
  }

  // node /path/to/server.js -> try to find package.json
  if (cmd === 'node' || cmd === 'node.exe') {
    for (const arg of args) {
      if (arg.startsWith('-')) continue;
      return undefined; // local path, handled by resolveLocalPath
    }
  }

  return undefined;
}

export function resolveLocalPath(server: MCPServerEntry): string | undefined {
  if (!server.command || !server.args?.length) return undefined;

  const cmd = server.command;
  const args = server.args;

  // node /path/to/server.js
  if (cmd === 'node' || cmd === 'node.exe') {
    for (const arg of args) {
      if (arg.startsWith('-')) continue;
      return resolve(arg);
    }
  }

  // Direct path execution
  if (cmd.startsWith('/') || cmd.startsWith('./') || cmd.startsWith('../')) {
    return resolve(cmd);
  }

  return undefined;
}

async function readSourceFile(filePath: string, fs: FSProvider): Promise<string | undefined> {
  try {
    const content = await fs.readFile(filePath);
    return content;
  } catch {
    return undefined;
  }
}

async function findMainEntry(dir: string, fs: FSProvider): Promise<string | undefined> {
  // Check package.json main field
  const pkgPath = join(dir, 'package.json');
  if (await fs.access(pkgPath)) {
    try {
      const pkg = JSON.parse(await fs.readFile(pkgPath));
      if (pkg.main) return join(dir, pkg.main);
      if (pkg.bin) {
        const binEntry = typeof pkg.bin === 'string' ? pkg.bin : Object.values(pkg.bin)[0];
        if (binEntry) return join(dir, binEntry as string);
      }
    } catch {
      // Fall through
    }
  }

  // Common entry points
  const candidates = ['index.js', 'index.ts', 'src/index.js', 'src/index.ts', 'main.js', 'server.js'];
  for (const candidate of candidates) {
    const fullPath = join(dir, candidate);
    if (await fs.access(fullPath)) return fullPath;
  }

  return undefined;
}

export async function resolveServerSources(
  servers: MCPServerEntry[],
  fs?: FSProvider,
): Promise<MCPServerSource[]> {
  const provider = fs ?? new LocalFSProvider();
  const sources: MCPServerSource[] = [];

  for (const server of servers) {
    const packageName = inferPackageName(server);
    const localPath = resolveLocalPath(server);

    let sourceCode: string | undefined;

    if (localPath) {
      sourceCode = await readSourceFile(localPath, provider);

      // If it's a directory, find the main entry
      if (!sourceCode) {
        const entry = await findMainEntry(localPath, provider);
        if (entry) {
          sourceCode = await readSourceFile(entry, provider);
        }
      }
    }

    sources.push({
      serverName: server.name,
      packageName,
      localPath,
      sourceCode,
    });
  }

  return sources;
}
