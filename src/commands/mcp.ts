import chalk from 'chalk';
import { writeFile } from 'node:fs/promises';
import { ScanEngine } from '../core/engine.js';
import { adapterRegistry } from '../adapters/registry.js';
import { checkRegistry } from '../core/check-registry.js';
import { getReporter } from '../reporting/index.js';
import { MCPDiscovery } from '../mcp/discovery.js';
import { resolveServerSources } from '../mcp/source-resolver.js';
import type { ScanOptions } from '../core/types.js';
import { logError } from '../core/debug.js';

export interface MCPScanCommandOptions {
  format: string;
  output?: string;
  path?: string[];
  color?: boolean;
}

export async function runMCPScan(options: MCPScanCommandOptions): Promise<void> {
  const discovery = new MCPDiscovery();

  try {
    const discoveryResult = options.path
      ? await discovery.discoverFromPaths(options.path)
      : await discovery.discover(process.platform, process.cwd());

    if (discoveryResult.totalServers === 0) {
      console.log(chalk.yellow('No MCP servers found. Nothing to scan.'));
      return;
    }

    console.log(chalk.dim(`Found ${discoveryResult.totalServers} MCP server(s) across ${discoveryResult.configs.length} config(s)`));

    // Resolve source code for servers with local paths
    const allServers = discoveryResult.configs.flatMap(c => c.servers);
    const serverSources = await resolveServerSources(allServers);

    const engine = new ScanEngine(adapterRegistry, checkRegistry);

    const scanOptions: ScanOptions = {
      format: options.format as 'terminal' | 'json' | 'sarif' | 'markdown',
    };

    const result = await engine.scanMCP(discoveryResult.configs, serverSources, scanOptions);

    const reporter = getReporter(scanOptions.format ?? 'terminal');
    const output = reporter.render(result);

    if (options.output) {
      await writeFile(options.output, output, 'utf-8');
      console.log(chalk.green(`Report written to ${options.output}`));
    } else {
      console.log(output);
    }

    const hasCritical = result.agents.some(a =>
      a.results.some(r => r.severity === 'critical' && !r.passed)
    );
    if (hasCritical) {
      process.exitCode = 1;
    }
  } catch (err) {
    logError(chalk.red('MCP scan failed:'), err);
    process.exitCode = 1;
  }
}

export async function runMCPList(options: { format: string; path?: string[] }): Promise<void> {
  const discovery = new MCPDiscovery();

  try {
    const result = options.path
      ? await discovery.discoverFromPaths(options.path)
      : await discovery.discover(process.platform, process.cwd());

    if (result.totalServers === 0) {
      console.log(chalk.yellow('No MCP servers found.'));
      return;
    }

    if (options.format === 'json') {
      console.log(JSON.stringify(result, null, 2));
      return;
    }

    console.log(chalk.bold(`\nMCP Servers (${result.totalServers} total)\n`));

    for (const config of result.configs) {
      console.log(chalk.cyan(`  ${config.source}`));
      console.log(chalk.dim(`  ${config.filePath}`));

      for (const server of config.servers) {
        console.log(`    ${chalk.bold(server.name)}`);
        console.log(`      Transport: ${server.transport}`);
        if (server.command) {
          const cmd = [server.command, ...(server.args ?? [])].join(' ');
          console.log(`      Command: ${cmd}`);
        }
        if (server.url) {
          console.log(`      URL: ${server.url}`);
        }
        if (server.env) {
          const envKeys = Object.keys(server.env);
          console.log(`      Env: ${envKeys.join(', ')}`);
        }
      }
      console.log('');
    }
  } catch (err) {
    logError(chalk.red('MCP list failed:'), err);
    process.exitCode = 1;
  }
}
