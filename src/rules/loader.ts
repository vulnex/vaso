import { join, extname, isAbsolute, resolve, dirname } from 'node:path';
import { lstat, realpath, stat } from 'node:fs/promises';
import { validateRuleFile, type DeclarativeRule, type ValidationError } from './schema.js';
import { pathExists } from '../core/utils.js';
import { parseYamlSafe } from '../core/yaml-safe.js';
import { INPUT_LIMITS } from '../core/input-file.js';
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
   * Not read at all (`rules` empty) unless `parseUntrusted` asks for their
   * rules (`vaso rules list`).
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
  // a rule file is a few KiB: a huge one is not read (as `--rules` and `rules validate` refuse it)
  const size = await stat(filePath).then(s => s.size, () => 0);
  if (size > INPUT_LIMITS.small) {
    return {
      filePath,
      source,
      rules: [],
      errors: [{ message: `Cannot read rule file: it is over ${INPUT_LIMITS.small / (1024 * 1024)} MiB` }],
      unreadable: true,
    };
  }
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

/** Larger trusted-projects files are ignored (a list of paths is a few lines). */
export const MAX_TRUSTED_PROJECTS_BYTES = 64 * 1024;

/**
 * Why ~/.vaso/trusted-projects can't be relied on, undefined when it can:
 * anyone who can change the file (or replace it, through ~/.vaso) could
 * make a repository trusted. The file — or a symlink's target — must be a
 * regular file the user owns that group and others can't write, in a
 * ~/.vaso with the same properties, and small.
 */
async function trustedFileProblem(file: string, fs: FSProvider): Promise<string | undefined> {
  const st = await stat(file);
  if (!st.isFile()) return `${file} is not a regular file — ignored`;
  if (st.size > MAX_TRUSTED_PROJECTS_BYTES) return `${file} is over ${MAX_TRUSTED_PROJECTS_BYTES / 1024} KiB — ignored`;
  return ownedFileProblem(file, 'ignored', fs);
}

/**
 * Write access beyond the owner: others' write bit, or the group's — unless
 * the group is the owner's private group (umask 002 distributions), which
 * reaches nobody else.
 */
function othersCanWrite(st: { mode: number; uid: number; gid: number }, privateGroups: ReadonlyMap<number, number>): boolean {
  return (st.mode & 0o002) !== 0 || ((st.mode & 0o020) !== 0 && privateGroups.get(st.gid) !== st.uid);
}

/** The user's own uid, or root's: a root-owned file or directory is as safe as one's own. */
function ownedBySelf(owner: number, uid: number | undefined): boolean {
  return uid === undefined || owner === uid || owner === 0;
}

/**
 * Why a file whose content steers VASO (~/.vaso/trusted-projects, a rule in
 * ~/.vaso/rules) can't be relied on, undefined when it can: someone else
 * could change it, or replace it through its directory. The file — or a
 * symlink's target — must be the user's own and only owner-writable; the
 * directory holding it and the directory holding the link's target must be
 * the user's own and owner-writable (a sticky directory is enough for the
 * target's: others can't rename or replace a file they don't own there).
 * `outcome` ends the sentence (`ignored`, `not loaded`).
 */
async function ownedFileProblem(file: string, outcome: string, fs: FSProvider): Promise<string | undefined> {
  if (process.platform === 'win32') return undefined;
  const uid = process.getuid?.();
  const groups = (await fs.privateGroups?.().catch(() => undefined)) ?? new Map<number, number>();
  const st = await stat(file);
  const link = await lstat(file);
  const dir = await stat(dirname(file));
  if (othersCanWrite(st, groups)) return `${file} is writable by group or others — ${outcome} (chmod 600 it to use it)`;
  if (!ownedBySelf(st.uid, uid) || !ownedBySelf(link.uid, uid)) return `${file} is not owned by you — ${outcome}`;
  if (othersCanWrite(dir, groups)) return `${dirname(file)} is writable by group or others — ${file} ${outcome} (chmod 700 it to use it)`;
  if (!ownedBySelf(dir.uid, uid)) return `${dirname(file)} is not owned by you — ${file} ${outcome}`;
  let real: string;
  try {
    real = await realpath(file);
  } catch {
    return undefined;
  }
  if (dirname(real) !== (await realpath(dirname(file)).catch(() => dirname(file)))) {
    const targetDir = await stat(dirname(real));
    if (othersCanWrite(targetDir, groups) && (targetDir.mode & 0o1000) === 0) {
      return `${file} links to ${real}, in a directory group or others can write (they could replace it) — ${outcome}`;
    }
  }
  return undefined;
}

/**
 * The projects the person running VASO trusts to supply rules, from
 * ~/.vaso/trusted-projects. The file is ignored (with a warning) when it
 * can't be relied on (trustedFileProblem). Relative entries are ignored.
 */
async function readTrustedProjects(
  fs: FSProvider,
  warn: (message: string) => void,
): Promise<Set<string>> {
  const file = join(fs.homedir(), TRUSTED_PROJECTS_FILE);
  const trusted = new Set<string>();
  let content: string;
  try {
    const problem = await trustedFileProblem(file, fs);
    if (problem) {
      warn(problem);
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

/**
 * Why ~/.vaso/rules as a whole can't be relied on: it, or ~/.vaso holding it,
 * is writable by others or not the user's (anyone could add or swap a rule).
 */
async function userRulesDirProblem(dir: string, fs: FSProvider): Promise<string | undefined> {
  if (process.platform === 'win32') return undefined;
  const uid = process.getuid?.();
  const groups = (await fs.privateGroups?.().catch(() => undefined)) ?? new Map<number, number>();
  for (const d of [dir, dirname(dir)]) {
    let st: Awaited<ReturnType<typeof stat>>;
    try {
      st = await stat(d);
    } catch {
      return undefined; // no rules directory: nothing to load
    }
    if (othersCanWrite(st, groups)) return `${d} is writable by group or others — the rules in ${dir} are not loaded (chmod 700 it to use them)`;
    if (!ownedBySelf(st.uid, uid)) return `${d} is not owned by you — the rules in ${dir} are not loaded`;
  }
  return undefined;
}

/** Whether two paths name the same existing directory. */
async function sameDirectory(a: string, b: string, fs: FSProvider): Promise<boolean> {
  try {
    return (await fs.realpath(a)) === (await fs.realpath(b));
  } catch {
    return false;
  }
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
  /** Parse untrusted project rule files too (listing them); otherwise they are only counted. */
  parseUntrusted?: boolean;
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

  const globalDir = join(provider.homedir(), '.vaso', 'rules');
  if (!options?.skipGlobal) {
    // A user rule may carry a fix `vaso fix` applies: like trusted-projects,
    // it counts only when nobody else could have written or replaced it
    const dirProblem = await userRulesDirProblem(globalDir, provider);
    for (const f of await discoverRuleFiles(globalDir, provider)) {
      let problem = dirProblem;
      try {
        problem ??= await ownedFileProblem(f, 'not loaded', provider);
      } catch {
        // unreadable: parseRuleFile says so
      }
      if (problem) {
        allErrors.push({ message: problem, file: f });
        continue;
      }
      files.push(await parseRuleFile(f, 'user', provider));
    }
  }

  // Run from the home, the project's rules are the user's own (~/.vaso/rules): one tier, loaded once
  const projectRulesDir = join(process.cwd(), '.vaso', 'rules');
  const sameAsUser = await sameDirectory(projectRulesDir, globalDir, provider);
  if (!options?.skipProject && !sameAsUser) {
    const projectFiles = await discoverRuleFiles(projectRulesDir, provider);
    if (projectFiles.length > 0) {
      const trusted = options?.projectRules === true
        || (await readTrustedProjects(provider, m => { trustWarning = m; })).has(projectDir);
      for (const f of projectFiles) {
        if (trusted) files.push(await parseRuleFile(f, 'project', provider));
        // An untrusted repository's file is never read for a scan: counted only
        else if (options?.parseUntrusted) untrustedProject.push(await parseRuleFile(f, 'project', provider));
        else untrustedProject.push({ filePath: f, source: 'project', rules: [], errors: [] });
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
