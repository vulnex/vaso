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
import { EXIT_USAGE } from '../core/exit-criteria.js';

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
  // skill (SKILL.md) is what SKL-007 checks for prompt injection, and the
  // canonical GhostApproval repo is just a disguised symlink plus a README —
  // SKL-007 and SKL-013 walk the directory itself, not the code-file list.
  // Bail only when there's genuinely nothing to look at.
  const contents = skillFiles.length === 0 ? await directoryContents(resolved) : { symlink: false, docs: 0 };

  if (skillFiles.length === 0 && !contents.symlink && contents.docs === 0) {
    console.error(chalk.yellow(`No code, documentation or symlinks found in ${resolved}. Nothing to audit.`));
    return;
  }

  console.error(
    chalk.dim(
      skillFiles.length > 0
        ? `Auditing ${skillFiles.length} file(s) in ${resolved}\n`
        : contents.docs > 0
          ? `Auditing ${contents.docs} documentation file(s) in ${resolved}\n`
          : `Auditing ${resolved} for symlink escapes\n`,
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

    const hasCritical = result.agents.some(a =>
      a.results.some(r => r.severity === 'critical' && !r.passed)
    );
    if (hasCritical) {
      process.exitCode = 1;
    }
  } catch (err) {
    logError(chalk.red('Skill audit failed:'), err);
    process.exitCode = EXIT_USAGE;
  }
}

const DOC_FILE = /\.(?:md|txt|rst)$/i;

/** Symlinks and documentation files (SKILL.md, README…) in the directory tree. */
async function directoryContents(dir: string): Promise<{ symlink: boolean; docs: number }> {
  try {
    const entries = await new LocalFSProvider().readdirEntries(dir, { recursive: true });
    return {
      symlink: entries.some((e) => e.isSymbolicLink),
      docs: entries.filter((e) => e.isFile && DOC_FILE.test(e.name)).length,
    };
  } catch {
    return { symlink: false, docs: 0 };
  }
}
