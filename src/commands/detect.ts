import chalk from 'chalk';
import { adapterRegistry } from '../adapters/registry.js';
import type { AgentInstallation, AgentType } from '../core/types.js';
import { logError } from '../core/debug.js';
import { writeFileEnsureDir } from '../core/utils.js';

export interface DetectCommandOptions {
  agent?: string;
  format: string;
  output?: string;
  outputDir?: string;
  allUsers?: boolean;
  verbose?: boolean;
  silent?: boolean;
  host?: string[];
  inventory?: string;
  sshKey?: string;
  sshTimeout?: string;
  sshRetries?: string;
  parallel?: string;
  snapshot?: string;
  saveSnapshot?: string;
}

function safeHostname(host: string): string {
  return host.replace(/[^A-Za-z0-9._-]/g, '_');
}

function parsePositiveInt(raw: string | undefined, fallback: number, label: string): number {
  if (raw === undefined) return fallback;
  const n = parseInt(raw, 10);
  if (isNaN(n) || n < 0) {
    throw new Error(`Invalid ${label} value "${raw}": expected a non-negative integer`);
  }
  return n;
}

async function emit(text: string, output?: string, silent?: boolean): Promise<void> {
  if (output) {
    await writeFileEnsureDir(output, text);
    if (!silent) console.log(chalk.green(`Report written to ${output}`));
  } else {
    console.log(text);
  }
}

export async function runDetect(options: DetectCommandOptions): Promise<void> {
  // Top-level --silent gate (covers snapshot, SSH, and local paths uniformly)
  if (options.silent && !options.output && !options.outputDir) {
    console.error(chalk.red('--silent requires -o/--output or --output-dir'));
    process.exitCode = 2;
    return;
  }
  if (options.output && options.outputDir) {
    console.error(chalk.red('--output and --output-dir are mutually exclusive'));
    process.exitCode = 2;
    return;
  }

  try {
    // Snapshot-based detection
    if (options.snapshot) {
      const results = await detectFromSnapshot(options);
      await renderResults(results, options);
      return;
    }

    // SSH remote detection
    if (options.host || options.inventory) {
      await detectRemoteHosts(options);
      return;
    }

    // Local detection
    let installations = await adapterRegistry.detectAll({
      allUsers: options.allUsers,
    });

    // Filter by agent type if specified
    if (options.agent) {
      const agentType = options.agent as AgentType;
      installations = installations.filter(i => i.agent === agentType);
    }

    await renderResults(installations, options);
  } catch (err) {
    logError(chalk.red('Detection failed:'), err);
    process.exitCode = 1;
  }
}

async function detectFromSnapshot(options: DetectCommandOptions): Promise<AgentInstallation[]> {
  const { readFile } = await import('node:fs/promises');
  const { SnapshotFSProvider } = await import('../core/snapshot-fs-provider.js');
  const raw = await readFile(options.snapshot!, 'utf-8');
  const snapshot = JSON.parse(raw);

  const errors: string[] = [];
  if (snapshot.version !== 1) errors.push(`Unsupported snapshot version: ${snapshot.version}`);
  if (!snapshot.platform) errors.push('Missing platform field');
  if (!snapshot.hostname) errors.push('Missing hostname field');
  if (!snapshot.files || typeof snapshot.files !== 'object') errors.push('Missing or invalid files field');

  if (errors.length > 0) {
    console.error(chalk.red('Invalid snapshot file:'));
    for (const e of errors) console.error(chalk.red(`  - ${e}`));
    process.exitCode = 1;
    return [];
  }

  const snapshotFs = new SnapshotFSProvider(snapshot);

  console.log(chalk.dim(`  Detecting agents from snapshot "${snapshot.hostname}" (${snapshot.platform})\n`));

  let installations = await adapterRegistry.detectAll({
    allUsers: options.allUsers,
    fs: snapshotFs,
  });

  if (options.agent) {
    installations = installations.filter(i => i.agent === (options.agent as AgentType));
  }

  return installations;
}

interface HostDetectResult {
  host: string;
  label?: string;
  installations: AgentInstallation[];
  error?: string;
}

async function detectRemoteHosts(options: DetectCommandOptions): Promise<void> {
  const { parseSSHTarget, executeRemoteProbeWithRetry } = await import('../transport/ssh.js');
  const { parseInventory } = await import('../transport/inventory.js');
  const { buildProbeManifest } = await import('../core/manifest-builder.js');
  const { SnapshotFSProvider } = await import('../core/snapshot-fs-provider.js');
  const { runConcurrent } = await import('../transport/multi-host.js');
  const { dirname, join } = await import('node:path');
  const { fileURLToPath } = await import('node:url');

  type SSHTarget = import('../transport/ssh.js').SSHTarget;

  const silent = !!options.silent;
  const log = (msg: string) => { if (!silent) console.log(msg); };

  let concurrency: number;
  let retries: number;
  try {
    concurrency = parsePositiveInt(options.parallel, 5, '--parallel');
    retries = parsePositiveInt(options.sshRetries, 0, '--ssh-retries');
    if (concurrency === 0) throw new Error('--parallel must be at least 1');
  } catch (err) {
    console.error(chalk.red((err as Error).message));
    process.exitCode = 2;
    return;
  }

  let targets: SSHTarget[] = [];

  if (options.host) {
    targets = options.host.map(h => {
      const t = parseSSHTarget(h);
      if (options.sshKey) t.identity = options.sshKey;
      return t;
    });
  }

  if (options.inventory) {
    const inventoryTargets = await parseInventory(options.inventory);
    for (const t of inventoryTargets) {
      if (options.sshKey && !t.identity) t.identity = options.sshKey;
    }
    targets.push(...inventoryTargets);
  }

  if (targets.length === 0) {
    console.error(chalk.red('No detection targets specified'));
    process.exitCode = 1;
    return;
  }

  const vasoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
  const probeBinDir = join(vasoRoot, 'probe', 'dist');
  const manifest = buildProbeManifest(adapterRegistry.getAdapters());
  const timeout = parseInt(options.sshTimeout ?? '60', 10) * 1000;

  if (options.saveSnapshot) {
    const { mkdir } = await import('node:fs/promises');
    await mkdir(options.saveSnapshot, { recursive: true });
  }

  if (options.outputDir) {
    const { mkdir } = await import('node:fs/promises');
    await mkdir(options.outputDir, { recursive: true });
  }

  log(chalk.bold(`\n  Detecting agents on ${targets.length} remote host(s)...\n`));

  async function processTarget(target: SSHTarget): Promise<HostDetectResult> {
    const start = Date.now();
    let outcome: HostDetectResult;
    try {
      const snapshot = await executeRemoteProbeWithRetry(
        target,
        { probeBinDir, manifest, timeout },
        {
          retries,
          onRetry: (t, attempt, err) => {
            log(chalk.yellow(`  Retry ${attempt}/${retries} for ${t.host}: ${err.message.split('\n')[0]}`));
          },
        },
      );

      if (options.saveSnapshot) {
        try {
          const { writeFile } = await import('node:fs/promises');
          const { join: joinPath } = await import('node:path');
          const safeHost = safeHostname(snapshot.hostname ?? target.host);
          const outPath = joinPath(options.saveSnapshot, `${safeHost}.json`);
          await writeFile(outPath, JSON.stringify(snapshot, null, 2), 'utf-8');
          log(chalk.dim(`  Saved snapshot for ${target.host} → ${outPath}`));
        } catch (err) {
          log(chalk.yellow(`  Warning: failed to save snapshot for ${target.host}: ${(err as Error).message}`));
        }
      }

      const snapshotFs = new SnapshotFSProvider(snapshot);
      let installations = await adapterRegistry.detectAll({
        allUsers: options.allUsers,
        fs: snapshotFs,
      });

      if (options.agent) {
        installations = installations.filter(i => i.agent === (options.agent as AgentType));
      }

      outcome = { host: snapshot.hostname ?? target.host, label: target.label, installations };
    } catch (err) {
      outcome = { host: target.host, label: target.label, installations: [], error: (err as Error).message };
    }

    // Per-host file output via --output-dir
    if (options.outputDir && !outcome.error) {
      try {
        const { writeFile } = await import('node:fs/promises');
        const { join: joinPath } = await import('node:path');
        const safeHost = safeHostname(outcome.host);
        const ext = options.format === 'json' ? 'json' : 'txt';
        const outPath = joinPath(options.outputDir, `${safeHost}.${ext}`);
        const text = options.format === 'json'
          ? JSON.stringify(outcome.installations, null, 2)
          : renderTerminal(outcome.installations, options.verbose);
        await writeFile(outPath, text, 'utf-8');
      } catch (err) {
        log(chalk.yellow(`  Warning: failed to write output for ${target.host}: ${(err as Error).message}`));
      }
    }

    // Live progress — fires as each host completes, even before all hosts are done
    const dur = `${Date.now() - start}ms`;
    const labelStr = target.label ?? `${target.user}@${target.host}`;
    if (outcome.error) {
      log(chalk.red(`  ✗ ${labelStr} (${dur}): ${outcome.error.split('\n')[0]}`));
    } else {
      log(chalk.green(`  ✓ ${labelStr} (${dur}) — ${outcome.installations.length} agent(s) detected`));
    }

    return outcome;
  }

  const results = await runConcurrent(targets, concurrency, processTarget);

  // When --output-dir is set, per-host files were already written above;
  // skip the combined-output rendering branch entirely.
  if (options.outputDir) {
    const wrote = results.filter(r => !r.error).length;
    log(chalk.green(`\n  Wrote ${wrote} report(s) to ${options.outputDir}/`));
    return;
  }

  // Render multi-host results
  if (options.format === 'json') {
    await emit(JSON.stringify(results, null, 2), options.output, silent);
  } else {
    const sections: string[] = [];
    for (const hr of results) {
      const hostLabel = hr.label ?? hr.host;
      sections.push(chalk.bold(`\n── ${hostLabel} ──\n`));

      if (hr.error) {
        sections.push(chalk.red(`  Error: ${hr.error}\n`));
        continue;
      }

      if (hr.installations.length === 0) {
        sections.push(chalk.yellow('  No agents detected.\n'));
        continue;
      }

      sections.push(renderTerminal(hr.installations, options.verbose));
    }

    const successCount = results.filter(r => !r.error).length;
    const failedCount = results.filter(r => r.error).length;
    const totalAgents = results.reduce((sum, r) => sum + r.installations.length, 0);

    sections.push(chalk.bold(`\n  ${successCount} host(s) scanned, ${totalAgents} agent(s) detected.`));
    if (failedCount > 0) {
      sections.push(chalk.red(`  ${failedCount} host(s) failed.`));
    }
    sections.push('');

    await emit(sections.join('\n'), options.output, silent);
  }
}

async function renderResults(installations: AgentInstallation[], options: DetectCommandOptions): Promise<void> {
  const text = options.format === 'json'
    ? renderJson(installations)
    : renderTerminal(installations, options.verbose);
  await emit(text, options.output, options.silent);
}

function renderJson(installations: AgentInstallation[]): string {
  return JSON.stringify(installations, null, 2);
}

function renderTerminal(installations: AgentInstallation[], verbose?: boolean): string {
  const lines: string[] = [];

  if (verbose) {
    const adapters = adapterRegistry.getAdapters();
    lines.push(chalk.dim('Adapters checked:'));
    for (const adapter of adapters) {
      const found = installations.some(i => i.agent === adapter.agent);
      const paths = adapter.getConfigPaths();
      const status = found ? chalk.green('found') : chalk.dim('not found');
      lines.push(chalk.dim(`  ${adapter.displayName}: ${status}`));
      for (const p of paths) {
        lines.push(chalk.dim(`    ${p}`));
      }
    }
    lines.push('');
  }

  if (installations.length === 0) {
    lines.push(chalk.yellow('No agents detected.'));
    return lines.join('\n');
  }

  for (const inst of installations) {
    // Build header with user/profile info
    const headerParts: string[] = [inst.agent];
    if (inst.user) headerParts.push(`user: ${inst.user}`);
    if (inst.agentName) headerParts.push(`agent: ${inst.agentName}`);
    if (inst.profile) headerParts.push(`profile: ${inst.profile}`);
    const header = headerParts.length > 1
      ? `${headerParts[0]} (${headerParts.slice(1).join(', ')})`
      : headerParts[0];

    lines.push(chalk.bold.cyan(header));
    if (inst.agentName) {
      lines.push(`  ${'Agent name:'.padEnd(14)} ${inst.agentName}`);
    }
    lines.push(`  ${'Version:'.padEnd(14)} ${inst.version ?? chalk.dim('unknown')}`);
    lines.push(`  ${'Install dir:'.padEnd(14)} ${inst.installDir}`);
    lines.push(`  ${'Config files:'.padEnd(14)} ${inst.configFiles.length}`);
    lines.push(`  ${'Skills dir:'.padEnd(14)} ${inst.skillsDir ?? chalk.dim('none')}`);

    if (inst.cliBinary) {
      lines.push(`  ${'CLI binary:'.padEnd(14)} ${inst.cliBinary}`);
    }

    if (inst.appBundle) {
      lines.push(`  ${'App bundle:'.padEnd(14)} ${inst.appBundle}`);
    }

    if (inst.gateway) {
      const gw = inst.gateway;
      const parts: string[] = [];
      if (gw.host) parts.push(gw.host);
      if (gw.port) parts.push(`:${gw.port}`);
      if (gw.tls) parts.push('(TLS)');
      if (gw.authMode) parts.push(`[${gw.authMode}]`);
      lines.push(`  ${'Gateway:'.padEnd(14)} ${parts.join(' ') || chalk.dim('none')}`);
    } else {
      lines.push(`  ${'Gateway:'.padEnd(14)} ${chalk.dim('none')}`);
    }

    if (inst.models && inst.models.length > 0) {
      const label = inst.models.length === 1 ? 'Model:' : `Models (${inst.models.length}):`;
      lines.push(`  ${label.padEnd(14)}`);
      for (const m of inst.models) {
        const id = m.provider ? `${m.provider}/${m.id}` : m.id;
        const suffix = m.via ? chalk.dim(` (${m.via})`) : '';
        lines.push(`    ${id}${suffix}`);
      }
    }

    lines.push('');
  }

  const subAgents = installations.filter(i => i.agentName);
  if (subAgents.length > 0) {
    lines.push(chalk.bold(`Found ${installations.length} agent(s) (${subAgents.length} sub-agent definitions).`));
  } else {
    lines.push(chalk.bold(`Found ${installations.length} agent(s).`));
  }

  return lines.join('\n');
}
