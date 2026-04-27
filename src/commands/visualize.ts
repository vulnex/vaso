import chalk from 'chalk';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
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

  let result: ScanResult;
  try {
    result = options.input
      ? await loadScanResult(options.input)
      : await runFreshScan(options);
  } catch (err) {
    logError('visualize: scan-result', err);
    console.error(chalk.red(`Failed to obtain scan result: ${(err as Error).message}`));
    process.exitCode = 1;
    return;
  }

  const adapters = new Map<string, AgentAdapter>();
  for (const a of adapterRegistry.getAdapters()) adapters.set(a.agent, a);

  const outputDir = resolve(options.output ?? DEFAULT_OUTPUT_DIR);
  try {
    const bundle = await emitBundle(result, { outputDir, format, diagrams, adapters });
    console.log(chalk.green(`Wrote ${bundle.files.length} file(s) to ${bundle.outputDir}`));
    for (const f of bundle.files) {
      const tag = f.diagram === 'readme' ? 'readme' : f.diagram;
      console.log(chalk.dim(`  ${tag.padEnd(20)} ${f.path}`));
    }
  } catch (err) {
    logError('visualize: emit-bundle', err);
    console.error(chalk.red(`Failed to write bundle: ${(err as Error).message}`));
    process.exitCode = 1;
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

async function loadScanResult(path: string): Promise<ScanResult> {
  const raw = await readFile(path, 'utf-8');
  const parsed = JSON.parse(raw);
  if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.agents)) {
    throw new Error(`File "${path}" does not look like a VASO scan result (missing 'agents' array)`);
  }
  return parsed as ScanResult;
}

async function runFreshScan(options: VisualizeCommandOptions): Promise<ScanResult> {
  const engine = new ScanEngine(adapterRegistry, checkRegistry);
  const scanOptions: ScanOptions = {
    agentFilter: options.agent,
    allUsers: options.allUsers,
  };
  return engine.scan(scanOptions);
}
