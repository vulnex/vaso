import chalk from 'chalk';
import { adapterRegistry } from '../adapters/registry.js';
import type { AgentInstallation, AgentType } from '../core/types.js';

export interface DetectCommandOptions {
  agent?: string;
  format: string;
  verbose?: boolean;
}

export async function runDetect(options: DetectCommandOptions): Promise<void> {
  try {
    let installations = await adapterRegistry.detectAll();

    // Filter by agent type if specified
    if (options.agent) {
      const agentType = options.agent as AgentType;
      installations = installations.filter(i => i.agent === agentType);
    }

    if (options.format === 'json') {
      renderJson(installations);
    } else {
      renderTerminal(installations, options.verbose);
    }
  } catch (err) {
    console.error(chalk.red('Detection failed:'), (err as Error).message);
    process.exitCode = 1;
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
    console.log(chalk.bold.cyan(`${inst.agent}`));
    console.log(`  ${'Version:'.padEnd(14)} ${inst.version ?? chalk.dim('unknown')}`);
    console.log(`  ${'Install dir:'.padEnd(14)} ${inst.installDir}`);
    console.log(`  ${'Config files:'.padEnd(14)} ${inst.configFiles.length}`);
    console.log(`  ${'Skills dir:'.padEnd(14)} ${inst.skillsDir ?? chalk.dim('none')}`);

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

  console.log(chalk.bold(`Found ${installations.length} agent(s).`));
}
