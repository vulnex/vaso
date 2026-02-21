import chalk from 'chalk';
import { PLUGIN_AGENTS } from '../plugins/types.js';
import type { PluginAgentType } from '../plugins/types.js';
import {
  installPlugin,
  uninstallPlugin,
  getPluginStatus,
} from '../plugins/installer.js';

function validateAgent(agent: string): PluginAgentType {
  if (!PLUGIN_AGENTS.includes(agent as PluginAgentType)) {
    throw new Error(`Invalid agent: ${agent}. Must be one of: ${PLUGIN_AGENTS.join(', ')}`);
  }
  return agent as PluginAgentType;
}

export async function runPluginInstall(options: { agent: string; force?: boolean }): Promise<void> {
  try {
    const agent = validateAgent(options.agent);
    const result = await installPlugin(agent, { force: options.force });
    console.log(chalk.green(`Plugin installed for ${agent}`));
    console.log(chalk.dim(`  Plugin: ${result.pluginPath}`));
    console.log(chalk.dim(`  Manifest: ${result.manifestPath}`));
  } catch (err) {
    const message = (err as Error).message;
    if (message.includes('already installed')) {
      console.error(chalk.red(message));
      console.error(chalk.dim('Use --force to overwrite the existing plugin.'));
    } else {
      console.error(chalk.red(`Plugin install failed: ${message}`));
    }
    process.exitCode = 1;
  }
}

export async function runPluginUninstall(options: { agent: string }): Promise<void> {
  try {
    const agent = validateAgent(options.agent);
    await uninstallPlugin(agent);
    console.log(chalk.green(`Plugin uninstalled for ${agent}`));
  } catch (err) {
    console.error(chalk.red(`Plugin uninstall failed: ${(err as Error).message}`));
    process.exitCode = 1;
  }
}

export async function runPluginStatus(options: { agent?: string; format?: string }): Promise<void> {
  try {
    const agent = options.agent ? validateAgent(options.agent) : undefined;
    const statuses = await getPluginStatus(agent);

    if (options.format === 'json') {
      console.log(JSON.stringify(statuses, null, 2));
      return;
    }

    console.log(chalk.bold('\nVASO Plugin Status\n'));

    for (const status of statuses) {
      const icon = status.installed ? chalk.green('●') : chalk.dim('○');
      const state = status.installed ? chalk.green('installed') : chalk.dim('not installed');
      console.log(`  ${icon} ${chalk.bold(status.agent)} — ${state}`);

      if (status.installed) {
        console.log(chalk.dim(`    Path: ${status.pluginPath}`));
        if (status.installedAt) {
          console.log(chalk.dim(`    Installed: ${status.installedAt}`));
        }
      }
    }
    console.log('');
  } catch (err) {
    console.error(chalk.red(`Plugin status failed: ${(err as Error).message}`));
    process.exitCode = 1;
  }
}
