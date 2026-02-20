import { Command } from 'commander';
import chalk from 'chalk';
import { adapterRegistry } from './adapters/registry.js';
import { openclawAdapter } from './adapters/openclaw.js';
import { nanoclawAdapter } from './adapters/nanoclaw.js';
import { picoclawAdapter } from './adapters/picoclaw.js';
import { registerAllChecks } from './checks/index.js';

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
registerAllChecks();

const program = new Command();

program
  .name('vaso')
  .description('VULNEX Agent Security Observer — security scanner for AI agent deployments')
  .version(VERSION, '-v, --version')
  .hook('preAction', () => {
    printBanner();
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
  .option('-a, --agent <type>', 'scan a specific agent (openclaw, nanoclaw, picoclaw)')
  .option('-f, --format <format>', 'output format (terminal, json, sarif, markdown)', 'terminal')
  .option('-o, --output <file>', 'write report to file')
  .option('--save-baseline', 'save scan results as baseline')
  .option('--diff', 'compare against saved baseline')
  .option('--no-color', 'disable colored output')
  .action(async (options) => {
    const { runScan } = await import('./commands/scan.js');
    await runScan(options);
  });

program
  .command('detect')
  .description('Detect installed AI agents')
  .option('-a, --agent <type>', 'detect a specific agent only (openclaw, nanoclaw, picoclaw)')
  .option('-f, --format <format>', 'output format (terminal, json)', 'terminal')
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
  .description('Update IOC database')
  .action(async () => {
    const { runUpdate } = await import('./commands/update.js');
    await runUpdate();
  });

const mcpCommand = program
  .command('mcp')
  .description('MCP server security scanning');

mcpCommand
  .command('scan')
  .description('Scan MCP server configurations for security issues')
  .option('-f, --format <format>', 'output format (terminal, json, sarif, markdown)', 'terminal')
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

program.parse();
