import chalk from 'chalk';
import { readInputFile, INPUT_LIMITS } from '../core/input-file.js';
import { join, resolve } from 'node:path';
import { ScanEngine } from '../core/engine.js';
import { adapterRegistry } from '../adapters/registry.js';
import { checkRegistry } from '../core/check-registry.js';
import type { AgentAdapter } from '../adapters/adapter.js';
import type { ScanResult, ScanOptions } from '../core/types.js';
import { emitBundle, ALL_DIAGRAMS, type DiagramKind } from '../visualizations/bundle.js';
import { isValidVisFormat, type VisFormat } from '../visualizations/serializers/format.js';
import { logError } from '../core/debug.js';

export interface VisualizeCommandOptions {
  input?: string;
  output?: string;
  visFormat?: string;
  diagrams?: string;
  agent?: string;
  allUsers?: boolean;
}

const DEFAULT_OUTPUT_DIR = './vaso-visualizations';

export async function runVisualize(options: VisualizeCommandOptions): Promise<void> {
  const format = parseFormat(options.visFormat);
  if (!format) {
    console.error(chalk.red(`Invalid --vis-format "${options.visFormat}". Use: toml, json, or yaml.`));
    process.exitCode = 2;
    return;
  }

  const diagrams = parseDiagrams(options.diagrams);
  if (!diagrams) {
    console.error(chalk.red(`Invalid --diagrams. Available: ${ALL_DIAGRAMS.join(', ')}.`));
    process.exitCode = 2;
    return;
  }

  let results: HostScan[];
  try {
    results = options.input
      ? await loadScanResults(options.input)
      : [{ result: await runFreshScan(options) }];
  } catch (err) {
    logError('visualize: scan-result', err);
    console.error(chalk.red(`Failed to obtain scan result: ${(err as Error).message}`));
    process.exitCode = 2;
    return;
  }

  const adapters = new Map<string, AgentAdapter>();
  for (const a of adapterRegistry.getAdapters()) adapters.set(a.agent, a);

  const baseDir = resolve(options.output ?? DEFAULT_OUTPUT_DIR);
  try {
    for (const { label, result } of results) {
      // Several hosts (a --host/--inventory report): one bundle per host
      const outputDir = results.length > 1 ? join(baseDir, safeDirName(label!)) : baseDir;
      const bundle = await emitBundle(result, { outputDir, format, diagrams, adapters });
      console.log(chalk.green(`Wrote ${bundle.files.length} file(s) to ${bundle.outputDir}`));
      for (const f of bundle.files) {
        const tag = f.diagram === 'readme' ? 'readme' : f.diagram;
        console.log(chalk.dim(`  ${tag.padEnd(20)} ${f.path}`));
      }
    }
  } catch (err) {
    logError('visualize: emit-bundle', err);
    console.error(chalk.red(`Failed to write bundle: ${(err as Error).message}`));
    process.exitCode = 2;
  }
}

function parseFormat(value: string | undefined): VisFormat | undefined {
  const v = value ?? 'toml';
  return isValidVisFormat(v) ? v : undefined;
}

function parseDiagrams(value: string | undefined): DiagramKind[] | undefined {
  if (!value) return [...ALL_DIAGRAMS];
  const parts = value.split(',').map(s => s.trim()).filter(Boolean);
  const out: DiagramKind[] = [];
  for (const p of parts) {
    if ((ALL_DIAGRAMS as string[]).includes(p)) out.push(p as DiagramKind);
    else return undefined;
  }
  return out;
}

interface HostScan { label?: string; result: ScanResult }

/**
 * A local `scan -f json` report is one ScanResult; a `--host`/`--inventory`
 * report (and each per-host file --output-dir writes) is a list of
 * `{ target, result | error }` entries. Hosts that failed have no result.
 */
async function loadScanResults(path: string): Promise<HostScan[]> {
  const raw = await readInputFile(path, INPUT_LIMITS.report);
  const parsed = JSON.parse(raw);
  if (parsed && typeof parsed === 'object' && Array.isArray(parsed.agents)) {
    return [{ result: parsed as ScanResult }];
  }
  if (Array.isArray(parsed)) {
    const hosts: HostScan[] = [];
    for (const entry of parsed) {
      const label = entry?.target?.label ?? entry?.target?.host ?? `host-${hosts.length + 1}`;
      if (entry?.result && Array.isArray(entry.result.agents)) hosts.push({ label: String(label), result: entry.result });
      else if (entry?.error) console.error(chalk.yellow(`Skipping ${label}: it was not scanned (${entry.error})`));
    }
    if (hosts.length > 0) return hosts;
    throw new Error(`File "${path}" has no scanned host to visualize`);
  }
  throw new Error(`File "${path}" does not look like a VASO scan result (missing 'agents' array)`);
}

function safeDirName(label: string): string {
  return label.replace(/[^A-Za-z0-9._@-]+/g, '_') || 'host';
}

async function runFreshScan(options: VisualizeCommandOptions): Promise<ScanResult> {
  const engine = new ScanEngine(adapterRegistry, checkRegistry);
  const scanOptions: ScanOptions = {
    agentFilter: options.agent,
    allUsers: options.allUsers,
  };
  return engine.scan(scanOptions);
}
