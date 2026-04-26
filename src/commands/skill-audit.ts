import chalk from 'chalk';
import { stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { writeFile } from 'node:fs/promises';
import { ScanEngine } from '../core/engine.js';
import { adapterRegistry } from '../adapters/registry.js';
import { checkRegistry } from '../core/check-registry.js';
import { getReporter } from '../reporting/index.js';
import { getSkillFiles } from '../core/utils.js';
import { logError } from '../core/debug.js';

export interface SkillAuditCommandOptions {
  format: string;
  output?: string;
  color?: boolean;
}

export async function runSkillAudit(skillPath: string, options: SkillAuditCommandOptions): Promise<void> {
  const resolved = resolve(skillPath);

  // Validate path exists and is a directory
  let pathStat;
  try {
    pathStat = await stat(resolved);
  } catch {
    console.error(chalk.red(`Path does not exist: ${resolved}`));
    process.exitCode = 1;
    return;
  }

  if (!pathStat.isDirectory()) {
    console.error(chalk.red(`Path is not a directory: ${resolved}`));
    process.exitCode = 1;
    return;
  }

  // Discover code files
  const skillFiles = await getSkillFiles(resolved);

  if (skillFiles.length === 0) {
    console.log(chalk.yellow(`No code files found in ${resolved}. Nothing to audit.`));
    return;
  }

  console.log(chalk.dim(`Auditing ${skillFiles.length} file(s) in ${resolved}\n`));

  try {
    const engine = new ScanEngine(adapterRegistry, checkRegistry);
    const result = await engine.scanSkill(resolved, skillFiles, {
      format: options.format as 'terminal' | 'json' | 'sarif' | 'markdown' | 'html',
    });

    const reporter = getReporter((options.format ?? 'terminal') as 'terminal' | 'json' | 'sarif' | 'markdown' | 'html');
    const output = reporter.render(result);

    if (options.output) {
      await writeFile(options.output, output, 'utf-8');
      console.log(chalk.green(`Report written to ${options.output}`));
    } else {
      console.log(output);
    }

    const hasCritical = result.agents.some(a =>
      a.results.some(r => r.severity === 'critical' && !r.passed)
    );
    if (hasCritical) {
      process.exitCode = 1;
    }
  } catch (err) {
    logError(chalk.red('Skill audit failed:'), err);
    process.exitCode = 1;
  }
}
