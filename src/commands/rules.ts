import { writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import chalk from 'chalk';
import { loadRules, validateRuleFile } from '../rules/index.js';
import { readFile } from 'node:fs/promises';
import YAML from 'yaml';

export interface RulesListOptions {
  format: string;
}

export async function runRulesList(options: RulesListOptions): Promise<void> {
  const result = await loadRules();

  if (result.allErrors.length > 0) {
    for (const err of result.allErrors) {
      const loc = err.rule ? ` (rule ${err.rule})` : '';
      console.log(chalk.yellow(`  Warning: ${err.file}${loc}: ${err.message}`));
    }
    console.log();
  }

  if (result.allRules.length === 0) {
    console.log(chalk.dim('  No declarative rules found.'));
    console.log(chalk.dim(`  Create rules in ~/.vaso/rules/ or .vaso/rules/`));
    console.log(chalk.dim(`  Run "vaso rules init" to generate a starter template.\n`));
    return;
  }

  if (options.format === 'json') {
    const output = result.allRules.map(r => ({
      id: r.id,
      name: r.name,
      category: r.category,
      severity: r.severity,
      description: r.description,
      type: r.config ? 'config' : r.pattern ? 'pattern' : 'file_exists',
    }));
    console.log(JSON.stringify(output, null, 2));
    return;
  }

  console.log(chalk.bold(`  Loaded ${result.allRules.length} declarative rule(s):\n`));

  const severityColor = (s: string) =>
    s === 'critical' ? chalk.red(s) : s === 'warning' ? chalk.yellow(s) : chalk.blue(s);

  for (const rule of result.allRules) {
    const type = rule.config ? 'config' : rule.pattern ? 'pattern' : 'file_exists';
    console.log(`  ${chalk.bold(rule.id)}  ${rule.name}`);
    console.log(`    ${severityColor(rule.severity)}  ${chalk.dim(type)}  ${chalk.dim(rule.description)}`);
  }

  console.log();

  // Show source files
  for (const file of result.files) {
    if (file.rules.length > 0) {
      console.log(chalk.dim(`  ${file.filePath} (${file.rules.length} rule(s))`));
    }
  }
  console.log();
}

export interface RulesValidateOptions {
  format?: string;
}

export async function runRulesValidate(filePath: string, options: RulesValidateOptions): Promise<void> {
  let content: string;
  try {
    content = await readFile(filePath, 'utf-8');
  } catch (err) {
    console.error(chalk.red(`  Error: Cannot read file: ${filePath}`));
    console.error(chalk.red(`  ${err instanceof Error ? err.message : String(err)}\n`));
    process.exitCode = 1;
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

  const { rules, errors } = validateRuleFile(data);

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
# Place this file in ~/.vaso/rules/ (global) or .vaso/rules/ (project-level).
# All rules are loaded automatically on scan.
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
}

export async function runRulesInit(options: RulesInitOptions): Promise<void> {
  const targetDir = options.dir ?? join(homedir(), '.vaso', 'rules');
  const targetFile = join(targetDir, 'example.yaml');

  try {
    await mkdir(targetDir, { recursive: true });
    await writeFile(targetFile, STARTER_TEMPLATE, 'utf-8');
    console.log(chalk.green(`  Created starter rule file: ${targetFile}\n`));
    console.log(chalk.dim('  Edit the file and run "vaso rules validate" to check it.'));
    console.log(chalk.dim('  Rules are loaded automatically on "vaso scan".\n'));
  } catch (err) {
    console.error(chalk.red(`  Error creating rule file: ${err instanceof Error ? err.message : String(err)}\n`));
    process.exitCode = 1;
  }
}
