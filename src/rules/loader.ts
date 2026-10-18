import { join, extname } from 'node:path';
import { validateRuleFile, type DeclarativeRule, type ValidationError } from './schema.js';
import { pathExists } from '../core/utils.js';
import { parseYamlSafe } from '../core/yaml-safe.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';

/**
 * Where a rule file came from. `user` (~/.vaso/rules/) and `explicit`
 * (`--rules`) are chosen by the person running VASO; `project` rules come
 * from `.vaso/rules/` in the working directory — a cloned repository can
 * ship them, so they are untrusted: they may add findings, but never carry a
 * fix and never replace a user or `--rules` rule.
 */
export type RuleSource = 'user' | 'project' | 'explicit';

export interface RuleFileResult {
  filePath: string;
  source: RuleSource;
  rules: DeclarativeRule[];
  errors: ValidationError[];
  /** The file could not be read at all (missing, a directory, no permission). */
  unreadable?: boolean;
}

/** A rule loaded from a file, with where it came from. */
export type LoadedRule = DeclarativeRule & { file: string; source: RuleSource };

export interface LoadResult {
  files: RuleFileResult[];
  allRules: LoadedRule[];
  allErrors: Array<ValidationError & { file: string }>;
  /** Rules skipped or changed on load (duplicate IDs, project fixes dropped). */
  warnings: Array<{ file: string; rule: string; message: string }>;
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

async function parseRuleFile(filePath: string, source: RuleSource, fs: FSProvider): Promise<RuleFileResult> {
  let content: string;
  try {
    content = await fs.readFile(filePath);
  } catch (err) {
    return {
      filePath,
      source,
      rules: [],
      errors: [{ message: `Cannot read rule file: ${err instanceof Error ? err.message : String(err)}` }],
      unreadable: true,
    };
  }
  try {
    const { rules, errors } = validateRuleFile(parseYamlSafe(content));
    return { filePath, source, rules, errors };
  } catch (err) {
    return {
      filePath,
      source,
      rules: [],
      errors: [{ message: `Failed to parse: ${err instanceof Error ? err.message : String(err)}` }],
    };
  }
}

const TIER_LABEL: Record<RuleSource, string> = { user: 'user', project: 'project', explicit: '--rules' };

/**
 * Load declarative rules from all discovery paths:
 * 1. User: ~/.vaso/rules/
 * 2. Project: .vaso/rules/ (relative to cwd) — untrusted, see RuleSource
 * 3. Extra paths from --rules CLI flag (replace a user rule of the same ID)
 *
 * Within one tier the first definition of an ID wins (files load sorted) and
 * a later one is skipped with a warning naming both files.
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
  const warnings: LoadResult['warnings'] = [];
  const ruleMap = new Map<string, LoadedRule>();

  if (!options?.skipGlobal) {
    const globalDir = join(provider.homedir(), '.vaso', 'rules');
    for (const f of await discoverRuleFiles(globalDir, provider)) files.push(await parseRuleFile(f, 'user', provider));
  }

  if (!options?.skipProject) {
    const projectDir = join(process.cwd(), '.vaso', 'rules');
    for (const f of await discoverRuleFiles(projectDir, provider)) files.push(await parseRuleFile(f, 'project', provider));
  }

  for (const p of options?.extraPaths ?? []) files.push(await parseRuleFile(p, 'explicit', provider));

  for (const file of files) {
    for (const err of file.errors) {
      allErrors.push({ ...err, file: file.filePath });
    }
    for (const parsed of file.rules) {
      let rule: LoadedRule = { ...parsed, file: file.filePath, source: file.source };
      const earlier = ruleMap.get(rule.id);
      if (earlier) {
        const where = `${TIER_LABEL[earlier.source]} rule ${earlier.file}`;
        if (earlier.source === rule.source) {
          warnings.push({ file: file.filePath, rule: rule.id, message: `duplicate rule ID — already defined in ${earlier.file}; this one is skipped` });
          continue;
        }
        if (rule.source === 'project') {
          warnings.push({ file: file.filePath, rule: rule.id, message: `project rule skipped — it would replace the ${where}` });
          continue;
        }
        if (earlier.source === 'project') {
          warnings.push({ file: earlier.file, rule: rule.id, message: `project rule skipped — the --rules rule ${file.filePath} defines the same ID` });
        } else {
          warnings.push({ file: file.filePath, rule: rule.id, message: `replaces the ${where}` });
        }
      }
      if (rule.source === 'project' && rule.fix?.set !== undefined) {
        // A repository's rule must not choose what `vaso fix` writes into the
        // user's own configs; guidance text stays
        const guidance = rule.fix.guidance;
        rule = { ...rule, fix: guidance !== undefined ? { guidance } : undefined };
        warnings.push({
          file: file.filePath,
          rule: rule.id,
          message: 'project rules can\'t carry fixes — its "fix.set" is ignored (move the rule to ~/.vaso/rules/ or pass it with --rules to keep the fix)',
        });
      }
      ruleMap.set(rule.id, rule);
    }
  }

  return {
    files,
    allRules: [...ruleMap.values()],
    allErrors,
    warnings,
  };
}
