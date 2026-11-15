import { writeFile, mkdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { homedir } from 'node:os';
import chalk from 'chalk';
import { loadRules, validateRuleFile, type DeclarativeRule } from '../rules/index.js';
import { checkRegistry } from '../core/check-registry.js';
import { readInputFile, INPUT_LIMITS } from '../core/input-file.js';
import YAML from 'yaml';
import { escapeControlChars } from '../reporting/text-safety.js';

/** A file name or rule text on one terminal line (names come from directory listings). */
const show = (s: string) => escapeControlChars(s, { lineBreaks: true });

export interface RulesListOptions {
  format: string;
}

export async function runRulesList(options: RulesListOptions): Promise<void> {
  const result = await loadRules();
  const untrusted = result.untrustedProject.flatMap(f => f.rules.map(r => ({ ...r, file: f.filePath })));
  const typeOf = (r: DeclarativeRule) => (r.config ? 'config' : r.pattern ? 'pattern' : 'file_exists');

  if (result.allErrors.length > 0 || result.warnings.length > 0 || result.trustWarning) {
    for (const err of result.allErrors) {
      const loc = err.rule ? ` (rule ${err.rule})` : '';
      console.error(chalk.yellow(`  Warning: ${show(err.file)}${loc}: ${err.message}`));
    }
    for (const w of result.warnings) {
      console.error(chalk.yellow(`  Warning: ${show(w.file)} (rule ${w.rule}): ${w.message}`));
    }
    if (result.trustWarning) console.error(chalk.yellow(`  Warning: ${show(result.trustWarning)}`));
    console.error();
  }

  if (options.format === 'json') {
    const output = [
      ...result.allRules.map(r => ({ r, status: 'loaded' })),
      ...untrusted.map(r => ({ r, status: 'untrusted' })),
    ].map(({ r, status }) => ({
      id: r.id,
      name: r.name,
      category: r.category,
      severity: r.severity,
      description: r.description,
      type: typeOf(r),
      file: r.file,
      status,
    }));
    console.log(JSON.stringify(output, null, 2));
    return;
  }

  if (result.allRules.length === 0 && untrusted.length === 0) {
    console.log(chalk.dim('  No declarative rules found.'));
    console.log(chalk.dim(`  Create rules in ~/.vaso/rules/ (or a project's .vaso/rules/, loaded only when trusted)`));
    console.log(chalk.dim(`  Run "vaso rules init" to generate a starter template.\n`));
    return;
  }

  const severityColor = (s: string) =>
    s === 'critical' ? chalk.red(s) : s === 'warning' ? chalk.yellow(s) : chalk.blue(s);
  const printRule = (rule: DeclarativeRule) => {
    console.log(`  ${chalk.bold(show(rule.id))}  ${show(rule.name)}`);
    console.log(`    ${severityColor(rule.severity)}  ${chalk.dim(typeOf(rule))}  ${chalk.dim(show(rule.description))}`);
  };

  if (result.allRules.length > 0) {
    console.log(chalk.bold(`  Loaded ${result.allRules.length} declarative rule(s):\n`));
    for (const rule of result.allRules) printRule(rule);
    console.log();
    for (const file of result.files) {
      if (file.rules.length > 0) {
        console.log(chalk.dim(`  ${show(file.filePath)} (${file.rules.length} rule(s))`));
      }
    }
    console.log();
  }

  if (untrusted.length > 0) {
    console.log(chalk.bold(`  ${untrusted.length} project rule(s) — untrusted (not loaded):\n`));
    for (const rule of untrusted) printRule(rule);
    console.log();
    for (const file of result.untrustedProject) {
      if (file.rules.length > 0) {
        console.log(chalk.dim(`  ${show(file.filePath)} (${file.rules.length} rule(s), untrusted)`));
      }
    }
    const dir = show(result.projectDir);
    console.log(chalk.dim(`\n  To load them: vaso scan --project-rules, or add ${dir} to ~/.vaso/trusted-projects\n`));
  }
}

export interface RulesValidateOptions {
  format?: string;
}

export async function runRulesValidate(filePath: string, options: RulesValidateOptions): Promise<void> {
  let content: string;
  try {
    content = await readInputFile(filePath, INPUT_LIMITS.small);
  } catch (err) {
    console.error(chalk.red(`  Error: Cannot read file: ${show(filePath)}`));
    console.error(chalk.red(`  ${show(err instanceof Error ? err.message : String(err))}\n`));
    process.exitCode = 2;
    return;
  }

  let data: unknown;
  try {
    data = YAML.parse(content);
  } catch (err) {
    console.error(chalk.red(`  Error: Invalid YAML syntax`));
    console.error(chalk.red(`  ${err instanceof Error ? err.message : String(err)}\n`));
    process.exitCode = 1;
    return;
  }

  const validated = validateRuleFile(data);
  const errors = [...validated.errors];
  // The IDs scan would skip: a built-in check's ID, or one used twice in the file
  const builtIn = new Set(checkRegistry.getAll().map(c => c.id));
  const seen = new Set<string>();
  const rules = validated.rules.filter(rule => {
    if (builtIn.has(rule.id)) {
      errors.push({ rule: rule.id, field: 'id', message: `"${rule.id}" is a built-in check ID — vaso scan skips this rule` });
      return false;
    }
    if (seen.has(rule.id)) {
      errors.push({ rule: rule.id, field: 'id', message: `"${rule.id}" is defined more than once — vaso scan keeps only the first` });
      return false;
    }
    seen.add(rule.id);
    return true;
  });

  if (options.format === 'json') {
    console.log(JSON.stringify({ valid: errors.length === 0, rules: rules.length, errors }, null, 2));
    return;
  }

  if (errors.length > 0) {
    console.log(chalk.red(`  ${errors.length} validation error(s) in ${filePath}:\n`));
    for (const err of errors) {
      const loc = [err.rule, err.field].filter(Boolean).join('.');
      console.log(chalk.red(`  ${loc ? `[${loc}] ` : ''}${err.message}`));
    }
    console.log();
    process.exitCode = 1;
  }

  if (rules.length > 0) {
    console.log(chalk.green(`  ${rules.length} valid rule(s) in ${filePath}\n`));
    for (const rule of rules) {
      const type = rule.config ? 'config' : rule.pattern ? 'pattern' : 'file_exists';
      console.log(`    ${chalk.bold(rule.id)}  ${rule.name}  ${chalk.dim(`(${type}, ${rule.severity})`)}`);
    }
    console.log();
  }

  if (errors.length === 0) {
    console.log(chalk.green('  All rules valid.\n'));
  }
}

const STARTER_TEMPLATE = `# VASO Declarative Rules
# Place this file in ~/.vaso/rules/ (global, loaded on every scan) or in a
# project's .vaso/rules/. Project rules load only when you trust the project:
# pass --project-rules, or add its absolute path to ~/.vaso/trusted-projects
# (one per line, owner-writable only). Even then their fix.set is ignored and
# they can't replace a global rule ID.
#
# Each rule must have exactly one type: config, pattern, or file_exists.
# See: https://github.com/vulnex/vaso#declarative-rules

rules:
  # Config value check — fail if a config field has a dangerous value
  - id: CUSTOM-001
    name: Disable debug mode
    category: config
    severity: warning
    description: Debug mode should be disabled in production
    # agents: [openclaw]         # optional: limit to specific agents
    # platforms: [linux, darwin]  # optional: limit to specific OS
    config:
      path: "server.debug"
      operator: "eq"
      value: true
    fix:
      set: "server.debug"
      value: false

  # Pattern match — scan config/skill files for regex matches
  - id: CUSTOM-002
    name: Hardcoded AWS access key
    category: config
    severity: critical
    description: AWS access keys must not be hardcoded in config files
    pattern:
      regex: "AKIA[0-9A-Z]{16}"
      target: "configs"        # configs | skills | all
      message: "AWS key found in {{file}}:{{line}}"

  # File existence — fail if a file exists (or does not exist)
  - id: CUSTOM-003
    name: No .env file in agent directory
    category: config
    severity: warning
    description: ".env files may contain secrets and should not be in the agent directory"
    file_exists:
      path: ".env"
      pass_when: "not-exists"
    fix:
      guidance: "Move secrets to a vault or environment variables and delete the .env file"
`;

export interface RulesInitOptions {
  dir?: string;
  force?: boolean;
}

export async function runRulesInit(options: RulesInitOptions): Promise<void> {
  const defaultDir = join(homedir(), '.vaso', 'rules');
  const targetDir = options.dir ?? defaultDir;
  const targetFile = join(targetDir, 'example.yaml');
  // Where `vaso scan` finds the file by itself: ~/.vaso/rules/, or ./.vaso/rules/ once the project is trusted
  const loadedByScan = resolve(targetDir) === defaultDir;
  const projectTier = resolve(targetDir) === join(process.cwd(), '.vaso', 'rules');

  try {
    // ~/.vaso also holds scan baselines: private, like they are (0700)
    await mkdir(targetDir, { recursive: true, ...(options.dir === undefined ? { mode: 0o700 } : {}) });
    // 'wx' fails on an existing file: never overwrite the user's rules unasked
    await writeFile(targetFile, STARTER_TEMPLATE, { encoding: 'utf-8', flag: options.force ? 'w' : 'wx' });
    console.log(chalk.green(`  Created starter rule file: ${targetFile}\n`));
    console.log(chalk.dim('  Edit the file and run "vaso rules validate" to check it.'));
    console.log(chalk.dim(loadedByScan
      ? '  Rules are loaded automatically on "vaso scan".\n'
      : projectTier
        ? `  Project rules load only when the project is trusted: "vaso scan --project-rules", or add ${show(process.cwd())} to ~/.vaso/trusted-projects. Their fix.set is never applied.\n`
        : `  "vaso scan" loads ~/.vaso/rules/ (and a trusted project's ./.vaso/rules/) only — pass this directory with --rules ${show(targetDir)}\n`));
  } catch (err) {
    const exists = (err as NodeJS.ErrnoException).code === 'EEXIST';
    console.error(chalk.red(exists
      ? `  ${targetFile} already exists — use --force to overwrite it\n`
      : `  Error creating rule file: ${err instanceof Error ? err.message : String(err)}\n`));
    process.exitCode = 2;
  }
}
