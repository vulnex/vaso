import { join, extname } from 'node:path';
import YAML from 'yaml';
import { validateRuleFile, type DeclarativeRule, type ValidationError } from './schema.js';
import { pathExists } from '../core/utils.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';

export interface RuleFileResult {
  filePath: string;
  rules: DeclarativeRule[];
  errors: ValidationError[];
}

export interface LoadResult {
  files: RuleFileResult[];
  allRules: DeclarativeRule[];
  allErrors: Array<ValidationError & { file: string }>;
}

const YAML_EXTENSIONS = new Set(['.yaml', '.yml']);

async function discoverRuleFiles(dir: string, fs: FSProvider): Promise<string[]> {
  if (!(await pathExists(dir, fs))) return [];

  const entries = await fs.readdirEntries(dir);
  return entries
    .filter(e => e.isFile && YAML_EXTENSIONS.has(extname(e.name)) && !e.name.startsWith('.'))
    .map(e => join(dir, e.name))
    .sort();
}

async function parseRuleFile(filePath: string, fs: FSProvider): Promise<RuleFileResult> {
  try {
    const content = await fs.readFile(filePath);
    const data = YAML.parse(content);
    const { rules, errors } = validateRuleFile(data);
    return { filePath, rules, errors };
  } catch (err) {
    return {
      filePath,
      rules: [],
      errors: [{ message: `Failed to parse: ${err instanceof Error ? err.message : String(err)}` }],
    };
  }
}

/**
 * Load declarative rules from all discovery paths.
 *
 * Priority (last wins on ID collision):
 * 1. Global: ~/.vaso/rules/
 * 2. Project: .vaso/rules/ (relative to cwd)
 * 3. Extra paths from --rules CLI flag
 */
export async function loadRules(options?: {
  extraPaths?: string[];
  skipGlobal?: boolean;
  skipProject?: boolean;
  fs?: FSProvider;
}): Promise<LoadResult> {
  const provider = options?.fs ?? new LocalFSProvider();
  const files: RuleFileResult[] = [];
  const allErrors: Array<ValidationError & { file: string }> = [];
  const ruleMap = new Map<string, DeclarativeRule>();

  // 1. Global rules
  if (!options?.skipGlobal) {
    const globalDir = join(provider.homedir(), '.vaso', 'rules');
    const globalFiles = await discoverRuleFiles(globalDir, provider);
    for (const f of globalFiles) {
      const result = await parseRuleFile(f, provider);
      files.push(result);
    }
  }

  // 2. Project rules
  if (!options?.skipProject) {
    const projectDir = join(process.cwd(), '.vaso', 'rules');
    const projectFiles = await discoverRuleFiles(projectDir, provider);
    for (const f of projectFiles) {
      const result = await parseRuleFile(f, provider);
      files.push(result);
    }
  }

  // 3. Extra paths (--rules flag)
  if (options?.extraPaths) {
    for (const p of options.extraPaths) {
      const result = await parseRuleFile(p, provider);
      files.push(result);
    }
  }

  // Collect rules and errors, dedup by ID (last wins)
  for (const file of files) {
    for (const err of file.errors) {
      allErrors.push({ ...err, file: file.filePath });
    }
    for (const rule of file.rules) {
      ruleMap.set(rule.id, rule);
    }
  }

  return {
    files,
    allRules: [...ruleMap.values()],
    allErrors,
  };
}
