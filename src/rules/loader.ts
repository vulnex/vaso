import { join, extname, isAbsolute, resolve } from 'node:path';
import { validateRuleFile, type DeclarativeRule, type ValidationError } from './schema.js';
import { pathExists } from '../core/utils.js';
import { parseYamlSafe } from '../core/yaml-safe.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';

/**
 * Where a rule file came from. `user` (~/.vaso/rules/) and `explicit`
 * (`--rules`) are chosen by the person running VASO; `project` rules come
 * from `.vaso/rules/` in the working directory — a cloned repository can
 * ship them, so they load only when the person trusts that project
 * (`--project-rules`, or its path in ~/.vaso/trusted-projects). Even then
 * they never carry a fix and never replace a user or `--rules` rule.
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
  /**
   * Project rule files found but not loaded: the project isn't trusted.
   * Parsed only to count their rules (`rules` holds the valid ones).
   */
  untrustedProject: RuleFileResult[];
  /** The project directory (realpath of the working directory). */
  projectDir: string;
  /** ~/.vaso/trusted-projects was there but ignored (why). */
  trustWarning?: string;
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

async function isDirectory(path: string, fs: FSProvider): Promise<boolean> {
  try {
    return (await fs.stat(path)).isDirectory();
  } catch {
    return false;
  }
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

/** One absolute project path per line; `#` starts a comment. */
export const TRUSTED_PROJECTS_FILE = join('.vaso', 'trusted-projects');

/**
 * The projects the person running VASO trusts to supply rules, from
 * ~/.vaso/trusted-projects. The file is ignored (with a warning) when group
 * or others can write it: anyone who can add a line could make a repository
 * trusted. Relative entries are ignored.
 */
async function readTrustedProjects(
  fs: FSProvider,
  warn: (message: string) => void,
): Promise<Set<string>> {
  const file = join(fs.homedir(), TRUSTED_PROJECTS_FILE);
  const trusted = new Set<string>();
  let content: string;
  try {
    const st = await fs.stat(file);
    if (!st.isFile()) return trusted;
    if (process.platform !== 'win32' && (st.mode & 0o022) !== 0) {
      warn(`${file} is writable by group or others — ignored (chmod 600 it to use it)`);
      return trusted;
    }
    content = await fs.readFile(file);
  } catch {
    return trusted;
  }
  for (const raw of content.split('\n')) {
    const line = raw.replace(/#.*/, '').trim();
    if (!line || !isAbsolute(line)) continue;
    trusted.add(resolve(line));
    try {
      trusted.add(await fs.realpath(line));
    } catch {
      // a project that doesn't exist (yet) is matched by its path as written
    }
  }
  return trusted;
}

const TIER_LABEL: Record<RuleSource, string> = { user: 'user', project: 'project', explicit: '--rules' };

/**
 * Load declarative rules from all discovery paths:
 * 1. User: ~/.vaso/rules/
 * 2. Project: .vaso/rules/ (relative to cwd) — only when the project is
 *    trusted (`projectRules`, or listed in ~/.vaso/trusted-projects); see RuleSource
 * 3. Extra paths from --rules CLI flag, files or directories (replace a user rule of the same ID)
 *
 * Within one tier the first definition of an ID wins (files load sorted) and
 * a later one is skipped with a warning naming both files.
 */
export async function loadRules(options?: {
  extraPaths?: string[];
  skipGlobal?: boolean;
  skipProject?: boolean;
  /** Trust the working directory's project rules (`--project-rules`). */
  projectRules?: boolean;
  fs?: FSProvider;
}): Promise<LoadResult> {
  const provider = options?.fs ?? new LocalFSProvider();
  const files: RuleFileResult[] = [];
  const untrustedProject: RuleFileResult[] = [];
  const allErrors: Array<ValidationError & { file: string }> = [];
  const warnings: LoadResult['warnings'] = [];
  const ruleMap = new Map<string, LoadedRule>();
  let trustWarning: string | undefined;
  let projectDir = process.cwd();
  try {
    projectDir = await provider.realpath(projectDir);
  } catch {
    // keep the path as given
  }

  if (!options?.skipGlobal) {
    const globalDir = join(provider.homedir(), '.vaso', 'rules');
    for (const f of await discoverRuleFiles(globalDir, provider)) files.push(await parseRuleFile(f, 'user', provider));
  }

  if (!options?.skipProject) {
    const projectFiles = await discoverRuleFiles(join(process.cwd(), '.vaso', 'rules'), provider);
    if (projectFiles.length > 0) {
      const trusted = options?.projectRules === true
        || (await readTrustedProjects(provider, m => { trustWarning = m; })).has(projectDir);
      for (const f of projectFiles) {
        (trusted ? files : untrustedProject).push(await parseRuleFile(f, 'project', provider));
      }
    }
  }

  for (const p of options?.extraPaths ?? []) {
    // `--rules <dir>` loads the directory's rule files, like ~/.vaso/rules
    if (await isDirectory(p, provider)) {
      for (const f of await discoverRuleFiles(p, provider)) files.push(await parseRuleFile(f, 'explicit', provider));
    } else {
      files.push(await parseRuleFile(p, 'explicit', provider));
    }
  }

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
        // Even a trusted repository's rule doesn't choose what `vaso fix`
        // writes into the user's own configs; guidance text stays
        const guidance = rule.fix.guidance;
        rule = { ...rule, fix: guidance !== undefined ? { guidance } : undefined };
        warnings.push({
          file: file.filePath,
          rule: rule.id,
          message: 'project rules can\'t carry fixes, even trusted — its "fix.set" is ignored (move the rule to ~/.vaso/rules/ or pass it with --rules to keep the fix)',
        });
      }
      ruleMap.set(rule.id, rule);
    }
  }

  return {
    files,
    untrustedProject,
    projectDir,
    ...(trustWarning !== undefined ? { trustWarning } : {}),
    allRules: [...ruleMap.values()],
    allErrors,
    warnings,
  };
}
