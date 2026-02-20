import chalk from 'chalk';
import type { ScanResult, CheckResult, Severity } from '../core/types.js';
import type { Reporter } from './reporter.js';

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

  render(result: ScanResult): string {
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
      const headerParts = [agent.agent];
      if (inst.user) headerParts.push(`user: ${inst.user}`);
      if (inst.profile) headerParts.push(`profile: ${inst.profile}`);
      const agentHeader = headerParts.length > 1
        ? `${headerParts[0]} (${headerParts.slice(1).join(', ')})`
        : headerParts[0];
      lines.push(chalk.bold.cyan(`Agent: ${agentHeader}`));
      lines.push(`  Install: ${inst.installDir}`);
      lines.push(`  Score: ${this.formatScore(agent.score)} (${agent.grade})`);
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
    lines.push(`  Overall: ${this.formatScore(result.totalScore)} (${result.totalGrade})`);
    lines.push('');

    return lines.join('\n');
  }

  private formatFinding(result: CheckResult): string {
    const colorFn = SEVERITY_COLORS[result.severity];
    const icon = SEVERITY_ICONS[result.severity];
    let line = `    ${colorFn(`[${icon}]`)} ${result.id}: ${result.name}`;
    line += `\n      ${result.message}`;
    if (result.evidence) {
      for (const e of result.evidence) {
        line += `\n      ${chalk.dim(`${e.file}${e.line ? `:${e.line}` : ''}`)}`;
        if (e.snippet) {
          line += `\n      ${chalk.dim(e.snippet)}`;
        }
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
