import chalk from 'chalk';
import { getLoadedPlugins, registeredAnything } from '../user-plugins/loader.js';
import { escapeControlChars } from '../reporting/text-safety.js';
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
    const state = stateLabel(plugin);
    const nameStr = chalk.bold(show(plugin.name)) + (plugin.version ? chalk.dim(` v${show(plugin.version)}`) : '');

    console.log(`  ${icon} ${nameStr} — ${state}`);

    if (plugin.description) {
      console.log(chalk.dim(`    ${show(plugin.description)}`));
    }

    const counts = formatRegisteredCounts(plugin);
    if (counts) {
      console.log(chalk.dim(`    Registered: ${counts}`));
    }

    console.log(chalk.dim(`    Path: ${show(plugin.path)}`));

    if (plugin.error) {
      console.log(chalk.red(`    Error: ${show(plugin.error)}`));
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
      console.error(chalk.red(`  Plugin "${show(name)}" not found.\n`));
      const available = plugins.map(p => show(p.name));
      if (available.length > 0) {
        console.log(chalk.dim(`  Available plugins: ${available.join(', ')}\n`));
      }
    }
    process.exitCode = 2;
    return;
  }

  if (options.format === 'json') {
    console.log(JSON.stringify(plugin, null, 2));
    return;
  }

  console.log(chalk.bold(`\nPlugin: ${show(plugin.name)}\n`));

  console.log(`  Status:      ${stateLabel(plugin)}`);
  console.log(`  Path:        ${chalk.dim(show(plugin.path))}`);
  if (plugin.version) console.log(`  Version:     ${show(plugin.version)}`);
  if (plugin.description) console.log(`  Description: ${show(plugin.description)}`);

  if (plugin.registered.checks.length > 0) {
    console.log(`\n  ${chalk.bold('Checks:')}    ${show(plugin.registered.checks.join(', '))}`);
  }
  if (plugin.registered.adapters.length > 0) {
    console.log(`  ${chalk.bold('Adapters:')}  ${show(plugin.registered.adapters.join(', '))}`);
  }
  if (plugin.registered.reporters.length > 0) {
    console.log(`  ${chalk.bold('Reporters:')} ${show(plugin.registered.reporters.join(', '))}`);
  }

  if (plugin.error) {
    console.log(`\n  ${chalk.red('Error:')} ${show(plugin.error)}`);
  }

  console.log('');
}

/** Plugin-supplied text (name, version, description, error, ids, path) for the terminal. */
function show(v: string | undefined): string {
  return escapeControlChars(v ?? '', { lineBreaks: true });
}

function stateLabel(plugin: LoadedPlugin): string {
  if (plugin.status === 'loaded') return chalk.green('loaded');
  return registeredAnything(plugin) ? chalk.yellow('loaded with errors') : chalk.red('error');
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
