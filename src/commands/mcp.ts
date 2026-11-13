import chalk from 'chalk';
import { escapeControlCharsDeep, stripColor } from '../reporting/text-safety.js';
import { writeFile } from 'node:fs/promises';
import { ScanEngine } from '../core/engine.js';
import { adapterRegistry } from '../adapters/registry.js';
import { checkRegistry } from '../core/check-registry.js';
import { getReporter } from '../reporting/index.js';
import { MCPDiscovery } from '../mcp/discovery.js';
import { resolveServerSources, resolveSourcePaths } from '../mcp/source-resolver.js';
import { maskArgSecrets } from '../mcp/config-secrets.js';
import { auditDependencies } from '../mcp/osv-audit.js';
import type { ScanOptions } from '../core/types.js';
import { logError } from '../core/debug.js';
import { maskCredentialsDeep, toReportJson } from '../reporting/serialize.js';
import { EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_USAGE, incompleteResults, parseFailOn, shouldFailScan } from '../core/exit-criteria.js';
import { describeFetchFailure } from '../mcp/package-fetcher.js';
import type { MCPConfigLoadError, MCPDiscoveryResult } from '../mcp/types.js';

/** Paths named with -p must exist and parse; otherwise nothing would be scanned silently. */
function reportUnreadable(result: MCPDiscoveryResult): boolean {
  for (const p of result.empty ?? []) console.error(chalk.yellow(`No MCP servers found in ${p} (no known config dialect matched)`));
  if (!result.unreadable?.length) return false;
  for (const p of result.unreadable) console.error(chalk.red(`Cannot read MCP config (missing or not valid JSON): ${p}`));
  process.exitCode = EXIT_USAGE;
  return true;
}

/** Discovered configs that exist but could not be read or parsed — their servers are not listed or scanned. */
function reportLoadErrors(errors: readonly MCPConfigLoadError[]): void {
  for (const e of errors) {
    console.error(chalk.yellow(`Could not ${e.stage === 'read' ? 'read' : 'parse'} ${e.source} MCP config ${e.filePath}: ${e.message} — its servers were not scanned`));
  }
}

export interface MCPScanCommandOptions {
  format: string;
  output?: string;
  path?: string[];
  color?: boolean;
  resolvePackages?: boolean;
  /** Look up dependency versions in OSV.dev (network, opt-in). */
  auditDeps?: boolean;
  /** MCP server source to analyze directly (entry files or checkouts). */
  source?: string[];
  failOn?: string;
}

export async function runMCPScan(options: MCPScanCommandOptions): Promise<void> {
  const discovery = new MCPDiscovery();
  const failOn = parseFailOn(options.failOn);
  if (!failOn) {
    process.exitCode = EXIT_USAGE;
    return;
  }

  try {
    // --source alone audits that code only; with -p, those configs as well.
    const sourceOnly = Boolean(options.source?.length) && !options.path;
    const discoveryResult: MCPDiscoveryResult = sourceOnly
      ? { configs: [], totalServers: 0 }
      : options.path
        ? await discovery.discoverFromPaths(options.path)
        : await discovery.discover(process.platform, process.cwd());
    if (reportUnreadable(discoveryResult)) return;

    const direct = options.source?.length ? await resolveSourcePaths(options.source) : { sources: [], unreadable: [] };
    // One bad --source path doesn't cost the others their scan: report it,
    // scan the rest, and exit 3 (incomplete) unless nothing was scannable.
    for (const p of direct.unreadable) console.error(chalk.red(`MCP server source not scanned (missing, unreadable or over the size limit): ${p}`));
    if (direct.unreadable.length > 0 && direct.sources.length === 0 && discoveryResult.totalServers === 0) {
      process.exitCode = EXIT_USAGE;
      return;
    }

    const loadErrors = discoveryResult.loadErrors ?? [];
    reportLoadErrors(loadErrors);
    if (discoveryResult.totalServers === 0 && direct.sources.length === 0) {
      console.error(chalk.yellow('No MCP servers found. Nothing to scan.'));
      // A machine-readable report is still written (an empty, clean one): CI
      // that uploads -o report.sarif / parses JSON otherwise finds no file.
      // An unreadable config is a finding, reported even with nothing else to scan
      if ((options.format ?? 'terminal') === 'terminal' && !options.output && loadErrors.length === 0) return;
    }

    if (discoveryResult.totalServers > 0) {
      console.error(chalk.dim(`Found ${discoveryResult.totalServers} MCP server(s) across ${discoveryResult.configs.length} config(s)`));
    }
    if (direct.sources.length > 0) {
      console.error(chalk.dim(`Analyzing source of ${direct.sources.length} MCP server(s) given with --source`));
    }

    // Resolve source code for servers with local paths. With --resolve-packages,
    // npm-packaged (npx) servers are also downloaded from the registry
    // (download-only, never executed) so the AST/tool checks can analyze them.
    const allServers = discoveryResult.configs.flatMap(c => c.servers);
    if (options.resolvePackages) {
      console.error(chalk.dim('Resolving npm-packaged servers from the registry (download-only, no execution)…'));
    }
    const serverSources = await resolveServerSources(allServers, {
      resolvePackages: options.resolvePackages,
    });
    if (options.resolvePackages) {
      const resolved = serverSources.filter(s => s.packageName && s.sourceCode).length;
      const packaged = serverSources.filter(s => s.packageName && !s.localPath).length;
      console.error(chalk.dim(`Resolved source for ${resolved}/${packaged} packaged server(s) (npm only; uvx/PyPI not analyzed).`));
      // Say why the rest weren't: no npm on PATH reads like "nothing to fetch" otherwise
      const why = new Map<string, number>();
      for (const s of serverSources) {
        if (!s.resolveFailure || s.sourceCode) continue;
        const reason = describeFetchFailure(s.resolveFailure);
        why.set(reason, (why.get(reason) ?? 0) + 1);
      }
      if (why.size > 0) {
        const list = [...why].map(([reason, n]) => `${reason} (${n})`).join(', ');
        const hint = serverSources.some(s => s.resolveFailure?.reason === 'npm-not-found')
          ? ' — install Node.js/npm or put npm on PATH to analyze them'
          : '';
        console.error(chalk.yellow(`Could not download packaged server source: ${list}${hint}. Their code was not analyzed.`));
      }
    }

    const allSources = [...serverSources, ...direct.sources];
    if (options.auditDeps) {
      console.error(chalk.dim('Looking up dependency versions in OSV.dev (package names and versions only)…'));
      const audit = await auditDependencies(allSources);
      if (audit.error) {
        console.error(chalk.yellow(`OSV.dev lookup failed (${audit.error}) — dependencies were checked against bundled advisories only.`));
      } else {
        const ranged = audit.rangeOnly > 0 ? `; ${audit.rangeOnly} known only by a declared range were not looked up` : '';
        console.error(chalk.dim(`Looked up ${audit.queried} dependency version(s): ${audit.vulnerable} with known vulnerabilities${ranged}.`));
      }
    }

    const engine = new ScanEngine(adapterRegistry, checkRegistry);

    const scanOptions: ScanOptions = {
      format: options.format as 'terminal' | 'json' | 'sarif' | 'markdown',
    };

    const result = await engine.scanMCP(discoveryResult.configs, allSources, scanOptions, loadErrors);

    const reporter = getReporter(scanOptions.format ?? 'terminal');
    const output = reporter.render(result);

    if (options.output) {
      await writeFile(options.output, stripColor(output), 'utf-8');
      console.error(chalk.green(`Report written to ${options.output}`));
    } else {
      console.log(output);
    }

    // A config that could not be read hid its servers: the scan is incomplete
    if (direct.unreadable.length > 0 || loadErrors.length > 0 || incompleteResults(result.agents.flatMap(a => a.results)).length > 0) {
      process.exitCode = EXIT_INCOMPLETE;
    } else if (shouldFailScan(result.agents.flatMap(a => a.results), failOn)) {
      process.exitCode = EXIT_FINDINGS;
    }
  } catch (err) {
    logError(chalk.red('MCP scan failed:'), err);
    process.exitCode = EXIT_USAGE;
  }
}

export async function runMCPList(options: { format: string; path?: string[] }): Promise<void> {
  const discovery = new MCPDiscovery();

  try {
    const result = options.path
      ? await discovery.discoverFromPaths(options.path)
      : await discovery.discover(process.platform, process.cwd());
    if (reportUnreadable(result)) return;
    reportLoadErrors(result.loadErrors ?? []);

    if (options.format === 'json') {
      // argv credentials (`--config '{"token":…}'`) masked as MCP-003 finds them
      const configs = result.configs.map(c => ({ ...c, servers: c.servers.map(sv => (sv.args ? { ...sv, args: maskArgSecrets(sv.args, sv.command) } : sv)) }));
      console.log(toReportJson({ ...result, configs }));
      return;
    }

    if (result.totalServers === 0) {
      console.log(chalk.yellow('No MCP servers found.'));
      return;
    }

    console.log(chalk.bold(`\nMCP Servers (${result.totalServers} total)\n`));

    // Server names, commands and URLs come from scanned config files
    for (const config of maskCredentialsDeep(escapeControlCharsDeep(result.configs, { lineBreaks: true }))) {
      console.log(chalk.cyan(`  ${config.source}`));
      console.log(chalk.dim(`  ${config.filePath}`));
      if (config.agents?.length) console.log(chalk.dim(`  Loaded by: ${config.agents.join(', ')}`));

      for (const server of config.servers) {
        console.log(`    ${chalk.bold(server.name)}`);
        console.log(`      Transport: ${server.transport}`);
        if (server.command) {
          const cmd = [server.command, ...maskArgSecrets(server.args ?? [], server.command)].join(' ');
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
    process.exitCode = EXIT_USAGE;
  }
}
