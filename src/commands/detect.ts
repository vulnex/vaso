import chalk from 'chalk';
import { adapterRegistry } from '../adapters/registry.js';
import type { AgentInstallation, AgentType } from '../core/types.js';
import { logError } from '../core/debug.js';

export interface DetectCommandOptions {
  agent?: string;
  format: string;
  allUsers?: boolean;
  verbose?: boolean;
  host?: string[];
  inventory?: string;
  sshKey?: string;
  sshTimeout?: string;
  snapshot?: string;
  saveSnapshot?: string;
}

export async function runDetect(options: DetectCommandOptions): Promise<void> {
  try {
    // Snapshot-based detection
    if (options.snapshot) {
      const results = await detectFromSnapshot(options);
      renderResults(results, options);
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

    renderResults(installations, options);
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
  const { parseSSHTarget } = await import('../transport/ssh.js');
  const { parseInventory } = await import('../transport/inventory.js');
  const { buildProbeManifest } = await import('../core/manifest-builder.js');
  const { SnapshotFSProvider } = await import('../core/snapshot-fs-provider.js');
  const { executeRemoteProbe } = await import('../transport/ssh.js');
  const { dirname, join } = await import('node:path');
  const { fileURLToPath } = await import('node:url');

  type SSHTarget = import('../transport/ssh.js').SSHTarget;

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

  console.log(chalk.bold(`\n  Detecting agents on ${targets.length} remote host(s)...\n`));

  const CONCURRENCY = 5;
  const results: HostDetectResult[] = [];

  async function processTarget(target: SSHTarget): Promise<HostDetectResult> {
    try {
      const snapshot = await executeRemoteProbe(target, {
        probeBinDir,
        manifest,
        timeout,
      });

      if (options.saveSnapshot) {
        try {
          const { writeFile, mkdir } = await import('node:fs/promises');
          const { join: joinPath } = await import('node:path');
          await mkdir(options.saveSnapshot, { recursive: true });
          const safeHost = (snapshot.hostname ?? target.host).replace(/[^A-Za-z0-9._-]/g, '_');
          const outPath = joinPath(options.saveSnapshot, `${safeHost}.json`);
          await writeFile(outPath, JSON.stringify(snapshot, null, 2), 'utf-8');
          console.log(chalk.dim(`  Saved snapshot for ${target.host} → ${outPath}`));
        } catch (err) {
          console.log(chalk.yellow(`  Warning: failed to save snapshot for ${target.host}: ${(err as Error).message}`));
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

      return { host: snapshot.hostname ?? target.host, label: target.label, installations };
    } catch (err) {
      return { host: target.host, label: target.label, installations: [], error: (err as Error).message };
    }
  }

  for (let i = 0; i < targets.length; i += CONCURRENCY) {
    const batch = targets.slice(i, i + CONCURRENCY);
    const batchResults = await Promise.all(batch.map(processTarget));
    results.push(...batchResults);
  }

  // Render multi-host results
  if (options.format === 'json') {
    console.log(JSON.stringify(results, null, 2));
  } else {
    for (const hr of results) {
      const hostLabel = hr.label ?? hr.host;
      console.log(chalk.bold(`\n── ${hostLabel} ──\n`));

      if (hr.error) {
        console.log(chalk.red(`  Error: ${hr.error}\n`));
        continue;
      }

      if (hr.installations.length === 0) {
        console.log(chalk.yellow('  No agents detected.\n'));
        continue;
      }

      renderTerminal(hr.installations, options.verbose);
    }

    const successCount = results.filter(r => !r.error).length;
    const failedCount = results.filter(r => r.error).length;
    const totalAgents = results.reduce((sum, r) => sum + r.installations.length, 0);

    console.log(chalk.bold(`\n  ${successCount} host(s) scanned, ${totalAgents} agent(s) detected.`));
    if (failedCount > 0) {
      console.log(chalk.red(`  ${failedCount} host(s) failed.`));
    }
    console.log('');
  }
}

function renderResults(installations: AgentInstallation[], options: DetectCommandOptions): void {
  if (options.format === 'json') {
    renderJson(installations);
  } else {
    renderTerminal(installations, options.verbose);
  }
}

function renderJson(installations: AgentInstallation[]): void {
  console.log(JSON.stringify(installations, null, 2));
}

function renderTerminal(installations: AgentInstallation[], verbose?: boolean): void {
  if (verbose) {
    const adapters = adapterRegistry.getAdapters();
    console.log(chalk.dim('Adapters checked:'));
    for (const adapter of adapters) {
      const found = installations.some(i => i.agent === adapter.agent);
      const paths = adapter.getConfigPaths();
      const status = found ? chalk.green('found') : chalk.dim('not found');
      console.log(chalk.dim(`  ${adapter.displayName}: ${status}`));
      for (const p of paths) {
        console.log(chalk.dim(`    ${p}`));
      }
    }
    console.log('');
  }

  if (installations.length === 0) {
    console.log(chalk.yellow('No agents detected.'));
    return;
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

    console.log(chalk.bold.cyan(header));
    if (inst.agentName) {
      console.log(`  ${'Agent name:'.padEnd(14)} ${inst.agentName}`);
    }
    console.log(`  ${'Version:'.padEnd(14)} ${inst.version ?? chalk.dim('unknown')}`);
    console.log(`  ${'Install dir:'.padEnd(14)} ${inst.installDir}`);
    console.log(`  ${'Config files:'.padEnd(14)} ${inst.configFiles.length}`);
    console.log(`  ${'Skills dir:'.padEnd(14)} ${inst.skillsDir ?? chalk.dim('none')}`);

    if (inst.cliBinary) {
      console.log(`  ${'CLI binary:'.padEnd(14)} ${inst.cliBinary}`);
    }

    if (inst.appBundle) {
      console.log(`  ${'App bundle:'.padEnd(14)} ${inst.appBundle}`);
    }

    if (inst.gateway) {
      const gw = inst.gateway;
      const parts: string[] = [];
      if (gw.host) parts.push(gw.host);
      if (gw.port) parts.push(`:${gw.port}`);
      if (gw.tls) parts.push('(TLS)');
      if (gw.authMode) parts.push(`[${gw.authMode}]`);
      console.log(`  ${'Gateway:'.padEnd(14)} ${parts.join(' ') || chalk.dim('none')}`);
    } else {
      console.log(`  ${'Gateway:'.padEnd(14)} ${chalk.dim('none')}`);
    }
    console.log('');
  }

  const subAgents = installations.filter(i => i.agentName);
  if (subAgents.length > 0) {
    console.log(chalk.bold(`Found ${installations.length} agent(s) (${subAgents.length} sub-agent definitions).`));
  } else {
    console.log(chalk.bold(`Found ${installations.length} agent(s).`));
  }
}
