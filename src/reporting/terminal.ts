import chalk from 'chalk';
import type { ScanResult, CheckResult, Severity } from '../core/types.js';
import { surfaceCounts } from './inventory-text.js';
import type { Reporter } from './reporter.js';
import { escapeControlCharsDeep } from './text-safety.js';

/** Evidence items listed per finding in terminal output. */
const MAX_TERMINAL_EVIDENCE = 20;
/** Examples listed when every item of a finding is mitigated. */
const MAX_MITIGATED_EXAMPLES = 5;

const SEVERITY_COLORS: Record<Severity, (s: string) => string> = {
  critical: chalk.red,
  warning: chalk.yellow,
  info: chalk.blue,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: 'x',
  warning: '!',
  info: 'i',
};

export class TerminalReporter implements Reporter {
  readonly format = 'terminal';

  render(scan: ScanResult): string {
    // Everything printed comes from scanned files; neutralize terminal
    // control sequences before any of it reaches the screen. Config contents
    // are never printed, so they are not copied.
    const result: ScanResult = {
      ...scan,
      agents: scan.agents.map(a => ({
        ...a,
        // Every printed field is one line: a newline in a server name or a
        // permission rule would otherwise forge report lines
        installation: { ...escapeControlCharsDeep({ ...a.installation, configFiles: [] }, { lineBreaks: true }), configFiles: a.installation.configFiles },
        results: escapeControlCharsDeep(a.results, { lineBreaks: true }),
      })),
    };
    const lines: string[] = [];

    lines.push('');
    lines.push(chalk.bold('VASO Security Scan Report'));
    lines.push(chalk.dim(`Timestamp: ${result.timestamp}`));
    lines.push('');

    if (result.agents.length === 0) {
      lines.push(chalk.yellow('No agents detected. Nothing to scan.'));
      return lines.join('\n');
    }

    for (const agent of result.agents) {
      const inst = agent.installation;
      const headerParts: string[] = [agent.agent];
      if (inst.user) headerParts.push(`user: ${inst.user}`);
      if (inst.agentName) headerParts.push(`agent: ${inst.agentName}`);
      if (inst.profile) headerParts.push(`profile: ${inst.profile}`);
      const agentHeader = headerParts.length > 1
        ? `${headerParts[0]} (${headerParts.slice(1).join(', ')})`
        : headerParts[0];
      lines.push(chalk.bold.cyan(`Agent: ${agentHeader}`));
      lines.push(`  Install: ${inst.installDir}`);
      lines.push(`  Score: ${this.formatScore(agent.score)} (${agent.grade})`);
      if (inst.inventory) lines.push(chalk.dim(`  Surface: ${surfaceCounts(inst.inventory)} (vaso detect --verbose lists them)`));
      lines.push('');

      const failed = agent.results.filter(r => !r.passed);
      const passed = agent.results.filter(r => r.passed);

      if (failed.length > 0) {
        lines.push(chalk.bold('  Findings:'));
        for (const result of failed) {
          lines.push(this.formatFinding(result));
        }
        lines.push('');
      }

      if (passed.length > 0) {
        lines.push(chalk.bold('  Passed:'));
        for (const result of passed) {
          lines.push(`    ${chalk.green('+')} ${result.id}: ${result.name}`);
        }
        lines.push('');
      }
    }

    lines.push(chalk.bold('Summary'));
    lines.push(`  Agents scanned: ${result.agents.length}`);
    lines.push(`  Total checks: ${result.summary.total}`);
    lines.push(`  Critical: ${chalk.red(String(result.summary.critical))}`);
    lines.push(`  Warnings: ${chalk.yellow(String(result.summary.warning))}`);
    lines.push(`  Info: ${chalk.blue(String(result.summary.info))}`);
    lines.push(`  Passed: ${chalk.green(String(result.summary.passed))}`);
    const shared = result.hostInventory?.sharedMcpServers ?? [];
    if (shared.length > 0) {
      const unpinned = shared.filter(g => g.unpinned).length;
      lines.push(`  Shared MCP servers: ${shared.length}${unpinned ? chalk.yellow(` (${unpinned} unpinned somewhere)`) : ''}`);
    }
    lines.push(`  Overall: ${this.formatScore(result.totalScore)} (${result.totalGrade})`);
    if (result.agents.length > 1) {
      // Headline is worst-case (weakest agent); show the mean as context.
      lines.push(`  Fleet average: ${result.fleetAverage}/100`);
    }
    lines.push('');

    return lines.join('\n');
  }

  private formatFinding(result: CheckResult): string {
    const colorFn = SEVERITY_COLORS[result.severity];
    const icon = SEVERITY_ICONS[result.severity];
    let line = `    ${colorFn(`[${icon}]`)} ${result.id}: ${result.name}`;
    line += `\n      ${result.message}`;
    if (result.evidence) {
      // Evidence can run to thousands of items (a large skill suite). List the
      // live ones up to a cap and summarize mitigated items — test/fixture code
      // or files unreachable through parent dirs; the file formats keep all.
      const live = result.evidence.filter(e => !e.mitigated);
      const mitigated = result.evidence.filter(e => e.mitigated);
      const shown = live.length > 0 ? live : mitigated;
      const cap = live.length > 0 ? MAX_TERMINAL_EVIDENCE : MAX_MITIGATED_EXAMPLES;
      for (const e of shown.slice(0, cap)) {
        line += `\n      ${chalk.dim(`${e.file}${e.line ? `:${e.line}` : ''}`)}`;
        if (e.snippet) {
          line += `\n      ${chalk.dim(e.snippet)}`;
        }
      }
      if (shown.length > cap) {
        line += `\n      ${chalk.dim(`… ${shown.length - cap} more (full list: --format json, markdown or html)`)}`;
      }
      if (live.length > 0 && mitigated.length > 0) {
        line += `\n      ${chalk.dim(`+ ${mitigated.length} mitigated (test/fixture code or unreachable through parent directories) — not listed`)}`;
      }
    }
    if (result.fixable) {
      line += `\n      ${chalk.green('Fixable:')} ${result.fixDescription ?? 'run vaso fix'}`;
    }
    return line;
  }

  private formatScore(score: number): string {
    if (score >= 90) return chalk.green(String(score));
    if (score >= 70) return chalk.yellow(String(score));
    return chalk.red(String(score));
  }
}
