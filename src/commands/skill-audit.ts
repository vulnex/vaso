import chalk from 'chalk';
import { stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { writeFile } from 'node:fs/promises';
import { ScanEngine } from '../core/engine.js';
import { adapterRegistry } from '../adapters/registry.js';
import { checkRegistry } from '../core/check-registry.js';
import { getReporter } from '../reporting/index.js';
import { getSkillFiles } from '../core/utils.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { logError } from '../core/debug.js';
import { EXIT_FINDINGS, EXIT_USAGE, parseFailOn, shouldFailScan } from '../core/exit-criteria.js';

export interface SkillAuditCommandOptions {
  format: string;
  output?: string;
  color?: boolean;
  failOn?: string;
}

export async function runSkillAudit(skillPath: string, options: SkillAuditCommandOptions): Promise<void> {
  const resolved = resolve(skillPath);
  const failOn = parseFailOn(options.failOn);
  if (!failOn) {
    process.exitCode = EXIT_USAGE;
    return;
  }

  // Validate path exists and is a directory
  let pathStat;
  try {
    pathStat = await stat(resolved);
  } catch {
    console.error(chalk.red(`Path does not exist: ${resolved}`));
    process.exitCode = EXIT_USAGE;
    return;
  }

  if (!pathStat.isDirectory()) {
    console.error(chalk.red(`Path is not a directory: ${resolved}`));
    process.exitCode = EXIT_USAGE;
    return;
  }

  // Discover code files
  const skillFiles = await getSkillFiles(resolved);

  // Even a directory with no code files is worth auditing: an instructions-only
  // skill (SKILL.md) is what SKL-007 checks for prompt injection, the
  // GhostApproval repo is a disguised symlink plus a README, and IOC checks
  // read package.json / config files and skill directory names. Bail only on
  // an empty directory.
  const entries = skillFiles.length === 0 ? await directoryEntryCount(resolved) : skillFiles.length;
  if (entries === 0) {
    console.error(chalk.yellow(`${resolved} is empty. Nothing to audit.`));
    return;
  }

  console.error(
    chalk.dim(
      skillFiles.length > 0
        ? `Auditing ${skillFiles.length} file(s) in ${resolved}\n`
        : `Auditing ${resolved} (no code files)\n`,
    ),
  );

  try {
    const engine = new ScanEngine(adapterRegistry, checkRegistry);
    const result = await engine.scanSkill(resolved, skillFiles, {
      format: options.format as 'terminal' | 'json' | 'sarif' | 'markdown' | 'html',
    });

    const reporter = getReporter((options.format ?? 'terminal') as 'terminal' | 'json' | 'sarif' | 'markdown' | 'html');
    const output = reporter.render(result);

    if (options.output) {
      await writeFile(options.output, output, 'utf-8');
      console.error(chalk.green(`Report written to ${options.output}`));
    } else {
      console.log(output);
    }

    if (shouldFailScan(result.agents.flatMap(a => a.results), failOn)) {
      process.exitCode = EXIT_FINDINGS;
    }
  } catch (err) {
    logError(chalk.red('Skill audit failed:'), err);
    process.exitCode = EXIT_USAGE;
  }
}

/** How many entries the directory tree holds (0 when unreadable). */
async function directoryEntryCount(dir: string): Promise<number> {
  try {
    return (await new LocalFSProvider().readdirEntries(dir, { recursive: true })).length;
  } catch {
    return 0;
  }
}
