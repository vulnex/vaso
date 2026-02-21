import { createInterface } from 'node:readline';
import chalk from 'chalk';
import type { CheckResult } from '../core/types.js';

export type PromptResponse = 'yes' | 'no' | 'all' | 'quit';

const SEVERITY_COLORS: Record<string, (s: string) => string> = {
  critical: chalk.red,
  warning: chalk.yellow,
  info: chalk.blue,
};

export async function promptForFix(finding: CheckResult): Promise<PromptResponse> {
  const colorFn = SEVERITY_COLORS[finding.severity] ?? chalk.white;

  console.log(`\n  ${chalk.bold(finding.id)} ${colorFn(`[${finding.severity}]`)}`);
  console.log(`  ${finding.message}`);

  if (finding.evidence?.length) {
    for (const e of finding.evidence) {
      const loc = e.line ? `${e.file}:${e.line}` : e.file;
      console.log(chalk.dim(`    ${loc}`));
      if (e.snippet) {
        console.log(chalk.dim(`    ${e.snippet}`));
      }
    }
  }

  if (finding.fixDescription) {
    console.log(`  ${chalk.cyan('Fix:')} ${finding.fixDescription}`);
  }

  const rl = createInterface({
    input: process.stdin,
    output: process.stderr,
  });

  return new Promise<PromptResponse>((resolve) => {
    rl.question('  Apply fix? [y]es / [n]o / [a]ll / [q]uit: ', (answer) => {
      rl.close();
      const normalized = answer.trim().toLowerCase();
      switch (normalized) {
        case 'y':
        case 'yes':
          resolve('yes');
          break;
        case 'a':
        case 'all':
          resolve('all');
          break;
        case 'q':
        case 'quit':
          resolve('quit');
          break;
        default:
          resolve('no');
          break;
      }
    });
  });
}
