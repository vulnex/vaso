import { dirname, extname, isAbsolute, join, normalize } from 'node:path';
import { classifySensitivePath } from '../analyzers/sensitive-paths.js';
import { parseYamlSafe } from './yaml-safe.js';
import { AsyncLocalStorage } from 'node:async_hooks';
import { parseTomlSafe } from './toml-safe.js';
import type { ParsedConfig } from './types.js';
import type { FSProvider } from './fs-provider.js';
import { parseJsonLenient } from './jsonc.js';
import { parseErrorMessage } from './parse-error.js';
import { LocalFSProvider } from './local-fs-provider.js';

/** A config file that exists but could not be read or parsed. Without this
 *  signal a corrupted config is indistinguishable from an absent one: adapters
 *  catch the loadConfig throw and skip the file, so the scan silently reports
 *  the agent as clean (or not installed) instead of "couldn't inspect it". */
export interface ConfigLoadError {
  filePath: string;
  stage: 'read' | 'parse';
  message: string;
  /** filePath is the unreadable directory every attempted config sits behind
   *  (one finding for the directory, not one per file name tried in it). */
  directory?: boolean;
}

const loadErrorStore = new AsyncLocalStorage<ConfigLoadError[]>();

/** Run `fn` with config-load error capture. Every loadConfig failure inside
 *  fn's async context (missing files excluded — probing paths that don't exist
 *  is normal) is recorded and returned alongside fn's result. AsyncLocalStorage
 *  keeps captures isolated per caller, so concurrently-detecting adapters
 *  don't see each other's errors. loadConfig's own throw/return behavior is
 *  unchanged — this is a side channel, not a new control flow. */
export async function captureConfigLoadErrors<T>(
  fn: () => Promise<T>,
): Promise<{ result: T; loadErrors: ConfigLoadError[] }> {
  const loadErrors: ConfigLoadError[] = [];
  const result = await loadErrorStore.run(loadErrors, fn);
  return { result, loadErrors };
}

/** Record a load failure on the active capture — also one found after the
 *  file itself parsed (an OpenClaw `$include` the agent would reject). */
export function recordLoadError(error: ConfigLoadError): void {
  const store = loadErrorStore.getStore();
  if (!store || store.some(e => e.filePath === error.filePath && e.stage === error.stage)) return;
  // Never the parser's code frame: the lines around an error are often credentials
  store.push({ ...error, message: parseErrorMessage(error.message) });
}

/**
 * Record a load failure for a config an adapter reads itself (binary formats
 * loadConfig can't parse, e.g. Windsurf's user_settings.pb). A missing file
 * is not a failure, as in loadConfig.
 */
export function recordConfigLoadFailure(filePath: string, stage: ConfigLoadError['stage'], error: unknown): void {
  if (stage === 'read' && isFileNotFound(error)) return;
  recordLoadError({ filePath, stage, message: errorMessage(error) });
}

/**
 * The directory that denied access to `filePath`, when the file itself can't
 * even be stat'ed (it sits under a directory without search permission). An
 * adapter tries several file names there; all of them fail the same way,
 * existing or not, so the directory is what gets reported.
 */
async function deniedAncestor(filePath: string, fs: FSProvider): Promise<string | undefined> {
  const code = (err: unknown) => (err as NodeJS.ErrnoException | null)?.code;
  try {
    await fs.stat(filePath);
    return undefined; // the file is reachable; it is the file that's unreadable
  } catch (err) {
    if (code(err) !== 'EACCES' && code(err) !== 'EPERM') return undefined;
  }
  for (let dir = dirname(filePath); dir !== dirname(dir); dir = dirname(dir)) {
    try {
      await fs.stat(dir);
      return dir;
    } catch {
      // still behind it
    }
  }
  return undefined;
}

/** Missing files are a normal probe outcome, not a load failure. Matches both
 *  node fs errors (`code === 'ENOENT'`) and SnapshotFSProvider's plain Errors
 *  whose message leads with "ENOENT". */
function isFileNotFound(error: unknown): boolean {
  // A directory where a config file is expected is not "missing": the agent
  // can't load it either, so recordReadFailure reports it (EISDIR)
  const code = (error as NodeJS.ErrnoException | null)?.code;
  if (code === 'ENOENT') return true;
  return error instanceof Error && error.message.startsWith('ENOENT');
}

/**
 * Record why reading `filePath` failed, as loadConfig does: nothing for a
 * missing file; the directory when the file sits behind an unreadable one;
 * EISDIR for a directory where the file is expected — a snapshot has no file
 * entry for it, only the directory's mode, so it is told apart by stat and
 * reads the same as locally; else the read error itself. For files adapters
 * and checks read without loadConfig.
 */
export async function recordReadFailure(filePath: string, fs: FSProvider, error: unknown): Promise<void> {
  if (isFileNotFound(error)) {
    if (await isDirectoryPath(filePath, fs)) recordLoadError({ filePath, stage: 'read', message: eisdirMessage(filePath) });
    return;
  }
  if ((error as NodeJS.ErrnoException | null)?.code === 'EISDIR') {
    recordLoadError({ filePath, stage: 'read', message: eisdirMessage(filePath) });
    return;
  }
  const dir = await deniedAncestor(filePath, fs).catch(() => undefined);
  recordLoadError(dir
    ? { filePath: dir, stage: 'read', message: `EACCES: permission denied, scandir '${dir}'`, directory: true }
    : { filePath, stage: 'read', message: errorMessage(error) });
}

/**
 * Record why listing directory `dir` failed; true when that is a failure.
 * A directory that isn't there — or that a snapshot knows only from its
 * parent's listing (no files of interest were collected in it) — holds
 * nothing to check, as a local listing of it would show: not a failure.
 * Nor is a regular file where the directory is expected (ENOTDIR): the agent
 * finds no rules there either, and a snapshot can't list it.
 */
export async function recordListFailure(dir: string, fs: FSProvider, error: unknown): Promise<boolean> {
  if (isFileNotFound(error) || isNotDirectory(error)) return false;
  const denied = await deniedAncestor(dir, fs).catch(() => undefined);
  recordLoadError(denied
    ? { filePath: denied, stage: 'read', message: `EACCES: permission denied, scandir '${denied}'`, directory: true }
    : { filePath: dir, stage: 'read', message: errorMessage(error), directory: true });
  return true;
}

function isNotDirectory(error: unknown): boolean {
  if ((error as NodeJS.ErrnoException | null)?.code === 'ENOTDIR') return true;
  return error instanceof Error && error.message.startsWith('ENOTDIR');
}

/** LocalFSProvider's own wording, so local and remote reports match. */
function eisdirMessage(filePath: string): string {
  return `EISDIR: illegal operation on a directory, read '${filePath}'`;
}

async function isDirectoryPath(filePath: string, fs: FSProvider): Promise<boolean> {
  try {
    return (await fs.stat(filePath)).isDirectory();
  } catch {
    return false;
  }
}

function errorMessage(error: unknown): string {
  return parseErrorMessage(error);
}

/**
 * Where a file really is in a sensitive location (a credential store, a shell
 * startup file, /etc) that its own path doesn't name — the file itself a
 * symlink there, or reached through a linked directory above it
 * (`~/.copilot → ~/.aws/cop` spells `~/.aws/cop/config.json` as
 * `~/.copilot/config.json`): the link target or real path, else undefined.
 * The probe never ships such content (`omitted: sensitive`, escapesToSink and
 * resolvedIntoSink in probe/sensitive_sinks.go); a local scan doesn't read it
 * either, so both report the same — and an SSH key is never parsed as a config.
 */
export async function linkedIntoSink(filePath: string, fs: FSProvider): Promise<string | undefined> {
  if (fs.kind === 'snapshot') return undefined;
  const named = new Set(classifySensitivePath(filePath));
  const outside = (t: string) => classifySensitivePath(t).some(label => !named.has(label));
  let real: string | undefined;
  try {
    real = normalize(await fs.realpath(filePath));
  } catch {
    // missing or unresolvable: the target as written is all there is
  }
  let raw: string | undefined;
  if (typeof fs.readlink === 'function') {
    try {
      raw = await fs.readlink(filePath);
    } catch {
      // not a symlink
    }
  }
  if (raw !== undefined) {
    const written = isAbsolute(raw) ? normalize(raw) : join(dirname(filePath), raw);
    if (outside(written) || (real !== undefined && outside(real))) return written;
  }
  // Through a linked directory above it (resolvedIntoSink)
  if (real !== undefined && real !== normalize(filePath) && outside(real)) return real;
  return undefined;
}

/** The error a read of such a file fails with (shaped like a snapshot's omitted content). */
export function sinkLinkError(filePath: string, target: string): Error & { omitted: 'sensitive' } {
  // Named for what the target is: /etc/hosts is system configuration, not a credential store
  const what = classifySensitivePath(target)[0] ?? 'a credential store, shell startup file or /etc';
  return Object.assign(new Error(`not read: reached through a symlink into ${what} (${target}): ${filePath}`), { omitted: 'sensitive' as const });
}

export async function loadConfig(filePath: string, fs?: FSProvider): Promise<ParsedConfig> {
  const provider = fs ?? new LocalFSProvider();

  let raw: string;
  let bom = false;
  const sink = await linkedIntoSink(filePath, provider);
  if (sink) {
    const error = sinkLinkError(filePath, sink);
    recordLoadError({ filePath, stage: 'read', message: error.message });
    throw error;
  }
  try {
    // Editors on Windows save JSON with a UTF-8 BOM; JSON.parse rejects it
    raw = await provider.readFile(filePath);
    bom = raw.startsWith('\uFEFF');
    if (bom) raw = raw.slice(1);
  } catch (error) {
    await recordReadFailure(filePath, provider, error);
    throw error;
  }

  const ext = extname(filePath).toLowerCase();
  const format = detectFormat(ext, filePath);

  let data: Record<string, unknown>;
  try {
    data = parseContent(raw, format);
  } catch (error) {
    recordLoadError({ filePath, stage: 'parse', message: errorMessage(error) });
    throw error;
  }

  // Unknown-format content that no parser accepted degrades to {} rather than
  // throwing (callers still get a usable ParsedConfig) — but it is still a
  // parse failure worth surfacing, unless the file is simply empty.
  if (data === UNPARSEABLE && raw.trim().length > 0) {
    recordLoadError({
      filePath,
      stage: 'parse',
      message: 'Content did not parse as JSON, YAML, or TOML',
    });
  }

  // A document whose top level is null or a scalar can't configure anything,
  // and handing it to checks as `data` would make key lookups throw. Arrays
  // stay: some agents keep list-shaped files (IronClaw's providers.json).
  if (data !== UNPARSEABLE && (data === null || typeof data !== 'object')) {
    recordLoadError({
      filePath,
      stage: 'parse',
      message: `Top-level value is ${data === null ? 'null' : `a ${typeof data}`}, not a mapping or list`,
    });
    data = {};
  }

  return { raw, format, filePath, data: data === UNPARSEABLE ? {} : data, ...(bom ? { bom } : {}) };
}

function detectFormat(ext: string, filePath: string): ParsedConfig['format'] {
  switch (ext) {
    case '.json':
    case '.jsonc':
    case '.json5':
      return 'json';
    case '.yaml':
    case '.yml':
      return 'yaml';
    case '.env':
      return 'env';
    case '.toml':
      return 'toml';
    default:
      if (filePath.endsWith('.env') || filePath.includes('.env.')) return 'env';
      // Try to detect by content
      return 'unknown';
  }
}

function parseContent(raw: string, format: ParsedConfig['format']): Record<string, unknown> {
  switch (format) {
    case 'json':
      return parseJsonLenient(raw) as Record<string, unknown>;
    case 'yaml':
      return (parseYamlSafe(raw) as Record<string, unknown> | null) ?? {};
    case 'env':
      return parseEnv(raw);
    case 'toml':
      return parseTomlSafe(raw);
    case 'unknown':
      return tryParse(raw);
  }
}

function parseEnv(raw: string): Record<string, unknown> {
  const data: Record<string, string> = {};
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) continue;
    // dotenv/shell style: `export KEY=value` sets KEY
    const key = trimmed.slice(0, eqIndex).trim().replace(/^export\s+/, '');
    let value = trimmed.slice(eqIndex + 1).trim();
    const quote = value[0];
    if ((quote === '"' || quote === "'") && value.indexOf(quote, 1) > 0) {
      // Quoted value: everything up to the closing quote (a trailing comment may follow)
      value = value.slice(1, value.indexOf(quote, 1));
    } else {
      // Unquoted value: ` #` starts an inline comment
      value = value.replace(/\s+#.*$/, '');
    }
    data[key] = value;
  }
  return data;
}

/** Sentinel distinguishing "all parsers rejected the content" from a file
 *  that legitimately parses to an empty object. Never escapes loadConfig. */
const UNPARSEABLE: Record<string, unknown> = {};

function tryParse(raw: string): Record<string, unknown> {
  try {
    return JSON.parse(raw);
  } catch {
    try {
      return (parseYamlSafe(raw) as Record<string, unknown> | null) ?? {};
    } catch {
      try {
        return parseTomlSafe(raw);
      } catch {
        return UNPARSEABLE;
      }
    }
  }
}
