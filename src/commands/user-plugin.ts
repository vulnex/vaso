import chalk from 'chalk';
import { getLoadedPlugins } from '../user-plugins/loader.js';
import type { LoadedPlugin } from '../user-plugins/types.js';

export async function runExtList(options: { format?: string }): Promise<void> {
  const plugins = getLoadedPlugins();

  if (options.format === 'json') {
    console.log(JSON.stringify(plugins, null, 2));
    return;
  }

  if (plugins.length === 0) {
    console.log(chalk.dim('  No user plugins loaded.\n'));
    console.log(chalk.dim('  Drop .js or .mjs files into ~/.vaso/plugins/ to extend VASO.\n'));
    return;
  }

  console.log(chalk.bold('\nUser Plugins\n'));

  for (const plugin of plugins) {
    const icon = plugin.status === 'loaded' ? chalk.green('●') : chalk.red('●');
    const state = plugin.status === 'loaded' ? chalk.green('loaded') : chalk.red('error');
    const nameStr = chalk.bold(plugin.name) + (plugin.version ? chalk.dim(` v${plugin.version}`) : '');

    console.log(`  ${icon} ${nameStr} — ${state}`);

    if (plugin.description) {
      console.log(chalk.dim(`    ${plugin.description}`));
    }

    const counts = formatRegisteredCounts(plugin);
    if (counts) {
      console.log(chalk.dim(`    Registered: ${counts}`));
    }

    console.log(chalk.dim(`    Path: ${plugin.path}`));

    if (plugin.error) {
      console.log(chalk.red(`    Error: ${plugin.error}`));
    }
  }

  console.log('');
}

export async function runExtInfo(name: string, options: { format?: string }): Promise<void> {
  const plugins = getLoadedPlugins();
  const plugin = plugins.find(p => p.name === name);

  if (!plugin) {
    if (options.format === 'json') {
      console.log(JSON.stringify({ error: `Plugin "${name}" not found` }));
    } else {
      console.error(chalk.red(`  Plugin "${name}" not found.\n`));
      const available = plugins.map(p => p.name);
      if (available.length > 0) {
        console.log(chalk.dim(`  Available plugins: ${available.join(', ')}\n`));
      }
    }
    process.exitCode = 1;
    return;
  }

  if (options.format === 'json') {
    console.log(JSON.stringify(plugin, null, 2));
    return;
  }

  console.log(chalk.bold(`\nPlugin: ${plugin.name}\n`));

  const status = plugin.status === 'loaded' ? chalk.green('loaded') : chalk.red('error');
  console.log(`  Status:      ${status}`);
  console.log(`  Path:        ${chalk.dim(plugin.path)}`);
  if (plugin.version) console.log(`  Version:     ${plugin.version}`);
  if (plugin.description) console.log(`  Description: ${plugin.description}`);

  if (plugin.registered.checks.length > 0) {
    console.log(`\n  ${chalk.bold('Checks:')}    ${plugin.registered.checks.join(', ')}`);
  }
  if (plugin.registered.adapters.length > 0) {
    console.log(`  ${chalk.bold('Adapters:')}  ${plugin.registered.adapters.join(', ')}`);
  }
  if (plugin.registered.reporters.length > 0) {
    console.log(`  ${chalk.bold('Reporters:')} ${plugin.registered.reporters.join(', ')}`);
  }

  if (plugin.error) {
    console.log(`\n  ${chalk.red('Error:')} ${plugin.error}`);
  }

  console.log('');
}

function formatRegisteredCounts(plugin: LoadedPlugin): string {
  const parts: string[] = [];
  if (plugin.registered.checks.length > 0) {
    parts.push(`${plugin.registered.checks.length} check${plugin.registered.checks.length !== 1 ? 's' : ''}`);
  }
  if (plugin.registered.adapters.length > 0) {
    parts.push(`${plugin.registered.adapters.length} adapter${plugin.registered.adapters.length !== 1 ? 's' : ''}`);
  }
  if (plugin.registered.reporters.length > 0) {
    parts.push(`${plugin.registered.reporters.length} reporter${plugin.registered.reporters.length !== 1 ? 's' : ''}`);
  }
  return parts.join(', ');
}
