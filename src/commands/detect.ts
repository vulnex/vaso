import chalk from 'chalk';
import { stripColor } from '../reporting/text-safety.js';
import { EXIT_INCOMPLETE, EXIT_USAGE } from '../core/exit-criteria.js';
import { adapterRegistry } from '../adapters/registry.js';
import { allUsersCoverageWarning } from '../adapters/openclaw.js';
import type { AgentInstallation, AgentType } from '../core/types.js';
import { logError } from '../core/debug.js';
import { writeFileEnsureDir, writeFileOwnerOnly } from '../core/utils.js';
import { VERSION } from '../version.js';
import { parseRemoteOptions, type RemoteOptionValues } from './remote-options.js';
import { HostFileNames, safeHostname } from '../transport/host-files.js';
import { join as joinPath } from 'node:path';
import { toReportJson } from '../reporting/serialize.js';

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


async function emit(text: string, output?: string, silent?: boolean): Promise<void> {
  if (output) {
    await writeFileEnsureDir(output, stripColor(text));
    if (!silent) console.error(chalk.green(`Report written to ${output}`));
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
  // Snapshots are what a remote scan collects; a local scan has none to save
  if (options.saveSnapshot && !options.host?.length && !options.inventory) {
    console.error(chalk.red('--save-snapshot applies to remote scans only (use with --host or --inventory)'));
    process.exitCode = 2;
    return;
  }
  let remoteValues: RemoteOptionValues;
  try {
    remoteValues = parseRemoteOptions(options);
  } catch (err) {
    console.error(chalk.red((err as Error).message));
    process.exitCode = 2;
    return;
  }

  try {
    // Snapshot-based detection
    if (options.snapshot) {
      const detected = await detectFromSnapshot(options);
      if (detected) await renderResults(detected.installations, options, detected.host);
      return;
    }

    // SSH remote detection
    if (options.host || options.inventory) {
      await detectRemoteHosts(options, remoteValues);
      return;
    }

    // Local detection
    if (options.allUsers && !options.silent) {
      const coverage = allUsersCoverageWarning();
      if (coverage) console.error(chalk.yellow(`  ! ${coverage}`));
    }
    let installations = await adapterRegistry.detectAll({
      allUsers: options.allUsers,
    });

    // Filter by agent type if specified
    if (options.agent) {
      const agentType = options.agent as AgentType;
      installations = installations.filter(i => i.agent === agentType);
    }

    const { hostname } = await import('node:os');
    await renderResults(installations, options, hostname());
  } catch (err) {
    logError(chalk.red('Detection failed:'), err);
    process.exitCode = EXIT_USAGE;
  }
}

async function detectFromSnapshot(options: DetectCommandOptions): Promise<{ installations: AgentInstallation[]; host: string } | undefined> {
  const { SnapshotFSProvider } = await import('../core/snapshot-fs-provider.js');
  const { loadSnapshotFile, SnapshotLoadError, snapshotErrorLines, SNAPSHOT_TRUNCATED_WARNING, probeVersionWarning } = await import('../core/snapshot-load.js');
  let snapshot;
  try {
    snapshot = await loadSnapshotFile(options.snapshot!);
  } catch (err) {
    if (!(err instanceof SnapshotLoadError)) throw err;
    for (const line of snapshotErrorLines(err)) console.error(chalk.red(line));
    process.exitCode = EXIT_USAGE;
    return undefined;
  }

  const snapshotFs = new SnapshotFSProvider(snapshot);

  console.error(chalk.dim(`  Detecting agents from snapshot "${snapshot.hostname}" (${snapshot.platform})\n`));
  if (snapshot.truncated) console.error(chalk.yellow(`  ! ${SNAPSHOT_TRUNCATED_WARNING}`));
  const probeWarning = probeVersionWarning(snapshot, VERSION);
  if (probeWarning) console.error(chalk.yellow(`  ! ${probeWarning}`));
  if (options.allUsers) {
    const coverage = allUsersCoverageWarning(snapshotFs);
    if (coverage) console.error(chalk.yellow(`  ! ${coverage}`));
  }

  let installations = await adapterRegistry.detectAll({
    allUsers: options.allUsers,
    fs: snapshotFs,
  });

  if (options.agent) {
    installations = installations.filter(i => i.agent === (options.agent as AgentType));
  }

  return { installations, host: snapshot.hostname };
}

interface HostDetectResult {
  host: string;
  label?: string;
  installations: AgentInstallation[];
  error?: string;
}

async function detectRemoteHosts(options: DetectCommandOptions, remoteValues: RemoteOptionValues): Promise<void> {
  const { parseSSHTarget, executeRemoteProbeWithRetry, uniqueTargets } = await import('../transport/ssh.js');
  const { parseInventory } = await import('../transport/inventory.js');
  const { buildProbeManifest } = await import('../core/manifest-builder.js');
  const { SnapshotFSProvider } = await import('../core/snapshot-fs-provider.js');
  const { runConcurrent } = await import('../transport/multi-host.js');
  const { dirname, join } = await import('node:path');
  const { fileURLToPath } = await import('node:url');

  type SSHTarget = import('../transport/ssh.js').SSHTarget;

  const silent = !!options.silent;
  const log = (msg: string) => { if (!silent) console.error(msg); };

  const { concurrency, retries, sshTimeoutSec } = remoteValues;

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

  const deduped = uniqueTargets(targets);
  targets = deduped.targets;
  for (const label of deduped.duplicates) console.error(chalk.yellow(`  ! ${label} is listed more than once — detecting it once`));

  if (targets.length === 0) {
    console.error(chalk.red('No detection targets specified'));
    process.exitCode = EXIT_USAGE;
    return;
  }

  const vasoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
  const probeBinDir = join(vasoRoot, 'probe', 'dist');
  const manifest = buildProbeManifest(adapterRegistry.getAdapters());
  const timeout = sshTimeoutSec * 1000;

  if (options.saveSnapshot) {
    const { mkdir } = await import('node:fs/promises');
    await mkdir(options.saveSnapshot, { recursive: true });
  }

  if (options.outputDir) {
    const { mkdir } = await import('node:fs/promises');
    await mkdir(options.outputDir, { recursive: true });
  }

  log(chalk.bold(`\n  Detecting agents on ${targets.length} remote host(s)...\n`));

  // One name per target for its snapshot and its report
  const hostFiles = new HostFileNames();
  const targetLabel = (t: SSHTarget) => t.label ?? `${t.user}@${t.host}`;

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
          const safeHost = hostFiles.claim(snapshot.hostname ?? target.host, targetLabel(target));
          const outPath = joinPath(options.saveSnapshot, `${safeHost}.json`);
          // Snapshots hold collected file contents by design — owner-only
          await writeFileOwnerOnly(outPath, JSON.stringify(snapshot, null, 2));
          log(chalk.dim(`  Saved snapshot for ${target.host} → ${outPath}`));
        } catch (err) {
          log(chalk.yellow(`  Warning: failed to save snapshot for ${target.host}: ${(err as Error).message}`));
        }
      }

      const snapshotFs = new SnapshotFSProvider(snapshot);
      if (options.allUsers) {
        const coverage = allUsersCoverageWarning(snapshotFs);
        if (coverage) log(chalk.yellow(`  ! ${target.label ?? target.host}: ${coverage}`));
      }
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
        const safeHost = hostFiles.claim(outcome.host, targetLabel(target));
        const ext = options.format === 'json' ? 'json' : 'txt';
        const outPath = joinPath(options.outputDir, `${safeHost}.${ext}`);
        const text = options.format === 'json'
          ? toReportJson(outcome.installations)
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
  // Scan incomplete: one or more hosts could not be reached/probed
  if (results.some(r => r.error)) process.exitCode = EXIT_INCOMPLETE;

  // When --output-dir is set, per-host files were already written above;
  // skip the combined-output rendering branch entirely.
  if (options.outputDir) {
    const wrote = results.filter(r => !r.error).length;
    log(chalk.green(`\n  Wrote ${wrote} report(s) to ${options.outputDir}/`));
    return;
  }

  // Render multi-host results
  if (options.format === 'json') {
    await emit(toReportJson(results), options.output, silent);
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

async function renderResults(installations: AgentInstallation[], options: DetectCommandOptions, host: string): Promise<void> {
  const text = options.format === 'json'
    ? renderJson(installations)
    : renderTerminal(installations, options.verbose);
  // --output-dir: the <dir>/<host>.<ext> layout multi-host detect uses
  const output = options.outputDir
    ? joinPath(options.outputDir, `${safeHostname(host)}.${options.format === 'json' ? 'json' : 'txt'}`)
    : options.output;
  await emit(text, output, options.silent);
}

function renderJson(installations: AgentInstallation[]): string {
  return toReportJson(installations);
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

    // Other copies at a different version (older globals, other nvm Nodes)
    for (const [i, copy] of (inst.otherInstalls ?? []).entries()) {
      const label = i === 0 ? 'Other copies:' : '';
      lines.push(`  ${label.padEnd(14)} ${copy.path} ${copy.version ? `(${copy.version})` : chalk.dim('(version unknown)')}`);
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
