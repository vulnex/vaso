import { Command } from 'commander';
import chalk from 'chalk';
import { adapterRegistry } from './adapters/registry.js';
import { openclawAdapter } from './adapters/openclaw.js';
import { nanoclawAdapter } from './adapters/nanoclaw.js';
import { picoclawAdapter } from './adapters/picoclaw.js';
import { ironclawAdapter } from './adapters/ironclaw.js';
import { nanobotAdapter } from './adapters/nanobot.js';
import { zeroclawAdapter } from './adapters/zeroclaw.js';
import { registerAllChecks } from './checks/index.js';
import { initIOCDatabase } from './ioc/database.js';
import { isFeedStale } from './ioc/updater.js';
import { initAdvisoryDatabase } from './advisory/database.js';
import { isAdvisoryFeedStale } from './advisory/updater.js';
import { loadUserPlugins } from './user-plugins/loader.js';

const VERSION = '0.1.0';

const BANNER = `
${chalk.red('██╗   ██╗ █████╗ ███████╗ ██████╗')}
${chalk.red('██║   ██║██╔══██╗██╔════╝██╔═══██╗')}
${chalk.red('██║   ██║███████║███████╗ ██║   ██║')}
${chalk.red('╚██╗ ██╔╝██╔══██║╚════██║██║   ██║')}
${chalk.red(' ╚████╔╝ ██║  ██║███████║╚██████╔╝')}
${chalk.red('  ╚═══╝  ╚═╝  ╚═╝╚══════╝ ╚═════╝')}
${chalk.dim(`  VULNEX Agent Security Observer v${VERSION}`)}
${chalk.dim('  Agent-agnostic security scanner for AI deployments')}
`;

function printBanner(): void {
  console.log(BANNER);
}

// Register adapters and checks
adapterRegistry.register(openclawAdapter);
adapterRegistry.register(nanoclawAdapter);
adapterRegistry.register(picoclawAdapter);
adapterRegistry.register(ironclawAdapter);
adapterRegistry.register(nanobotAdapter);
adapterRegistry.register(zeroclawAdapter);
registerAllChecks();

const program = new Command();

program
  .name('vaso')
  .description('VULNEX Agent Security Observer — security scanner for AI agent deployments')
  .version(VERSION, '-v, --version')
  .hook('preAction', async (thisCommand) => {
    printBanner();

    // Load user plugins from ~/.vaso/plugins/
    const userPlugins = await loadUserPlugins();
    for (const p of userPlugins) {
      if (p.status === 'error') {
        console.log(chalk.yellow(`  Warning: user plugin "${p.name}" failed to load: ${p.error}\n`));
      }
    }

    await initIOCDatabase();
    await initAdvisoryDatabase();

    // Warn about stale feeds for non-update commands
    if (thisCommand.name() !== 'update') {
      if (isFeedStale()) {
        console.log(
          chalk.yellow('  IOC feed is stale or missing. Run `vaso update` for latest threat data.\n'),
        );
      }
      if (isAdvisoryFeedStale()) {
        console.log(
          chalk.yellow('  Advisory feed is stale or missing. Run `vaso update` for latest advisories.\n'),
        );
      }
    }
  });

// Show banner on help
const originalHelp = program.helpInformation.bind(program);
program.helpInformation = function () {
  printBanner();
  return originalHelp();
};

program
  .command('scan')
  .description('Scan installed AI agents for security issues')
  .option('-a, --agent <type>', 'scan a specific agent (openclaw, nanoclaw, picoclaw, ironclaw, nanobot, zeroclaw)')
  .option('-f, --format <format>', 'output format (terminal, json, sarif, markdown, html)', 'terminal')
  .option('-o, --output <file>', 'write report to file')
  .option('--save-baseline', 'save scan results as baseline')
  .option('--diff', 'compare against saved baseline')
  .option('--all-users', 'scan all user accounts (requires root/sudo)')
  .option('--no-color', 'disable colored output')
  .action(async (options) => {
    const { runScan } = await import('./commands/scan.js');
    await runScan(options);
  });

program
  .command('detect')
  .description('Detect installed AI agents')
  .option('-a, --agent <type>', 'detect a specific agent only (openclaw, nanoclaw, picoclaw, ironclaw, nanobot, zeroclaw)')
  .option('-f, --format <format>', 'output format (terminal, json)', 'terminal')
  .option('--all-users', 'detect across all user accounts (requires root/sudo)')
  .option('--verbose', 'show search paths checked for each adapter')
  .action(async (options) => {
    const { runDetect } = await import('./commands/detect.js');
    await runDetect(options);
  });

program
  .command('fix')
  .description('Auto-fix detected security issues')
  .option('-a, --agent <type>', 'fix a specific agent')
  .option('--dry-run', 'show what would be fixed without making changes')
  .option('-y, --yes', 'apply all fixes without confirmation')
  .option('--rollback', 'rollback the last fix operation')
  .action(async (options) => {
    const { runFix } = await import('./commands/fix.js');
    await runFix(options);
  });

program
  .command('update')
  .description('Update IOC database from remote threat feed')
  .option('--url <url>', 'custom feed URL')
  .option('--force', 'force update even if feed is not stale')
  .action(async (options) => {
    const { runUpdate } = await import('./commands/update.js');
    await runUpdate(options);
  });

const mcpCommand = program
  .command('mcp')
  .description('MCP server security scanning');

mcpCommand
  .command('scan')
  .description('Scan MCP server configurations for security issues')
  .option('-f, --format <format>', 'output format (terminal, json, sarif, markdown, html)', 'terminal')
  .option('-o, --output <file>', 'write report to file')
  .option('-p, --path <paths...>', 'specific config file paths to scan')
  .option('--no-color', 'disable colored output')
  .action(async (options) => {
    const { runMCPScan } = await import('./commands/mcp.js');
    await runMCPScan(options);
  });

mcpCommand
  .command('list')
  .description('List discovered MCP server configurations')
  .option('-f, --format <format>', 'output format (terminal, json)', 'terminal')
  .option('-p, --path <paths...>', 'specific config file paths to scan')
  .action(async (options) => {
    const { runMCPList } = await import('./commands/mcp.js');
    await runMCPList(options);
  });

const skillCommand = program
  .command('skill')
  .description('Skill security auditing');

skillCommand
  .command('audit')
  .description('Audit a local skill directory for security issues before installation')
  .argument('<path>', 'path to skill directory')
  .option('-f, --format <format>', 'output format (terminal, json, sarif, markdown, html)', 'terminal')
  .option('-o, --output <file>', 'write report to file')
  .option('--no-color', 'disable colored output')
  .action(async (path: string, options: Record<string, unknown>) => {
    const { runSkillAudit } = await import('./commands/skill-audit.js');
    await runSkillAudit(path, options as { format: string; output?: string; color?: boolean });
  });

const pluginCommand = program
  .command('plugin')
  .description('Manage agent security plugins');

pluginCommand
  .command('install')
  .description('Install VASO security plugin for an agent framework')
  .requiredOption('-a, --agent <type>', 'agent framework (openclaw, nanoclaw, picoclaw)')
  .option('--force', 'overwrite existing plugin')
  .action(async (options) => {
    const { runPluginInstall } = await import('./commands/plugin.js');
    await runPluginInstall(options);
  });

pluginCommand
  .command('uninstall')
  .description('Uninstall VASO security plugin for an agent framework')
  .requiredOption('-a, --agent <type>', 'agent framework (openclaw, nanoclaw, picoclaw)')
  .action(async (options) => {
    const { runPluginUninstall } = await import('./commands/plugin.js');
    await runPluginUninstall(options);
  });

pluginCommand
  .command('status')
  .description('Show plugin installation status')
  .option('-a, --agent <type>', 'check a specific agent only')
  .option('-f, --format <format>', 'output format (terminal, json)', 'terminal')
  .action(async (options) => {
    const { runPluginStatus } = await import('./commands/plugin.js');
    await runPluginStatus(options);
  });

const extCommand = program
  .command('ext')
  .description('Manage user plugins');

extCommand
  .command('list')
  .description('List loaded user plugins')
  .option('-f, --format <format>', 'output format (terminal, json)', 'terminal')
  .action(async (options) => {
    const { runExtList } = await import('./commands/user-plugin.js');
    await runExtList(options);
  });

extCommand
  .command('info')
  .description('Show details for a user plugin')
  .argument('<name>', 'plugin name')
  .option('-f, --format <format>', 'output format (terminal, json)', 'terminal')
  .action(async (name: string, options: Record<string, unknown>) => {
    const { runExtInfo } = await import('./commands/user-plugin.js');
    await runExtInfo(name, options as { format?: string });
  });

program.parse();
