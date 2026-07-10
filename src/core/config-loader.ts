import { extname } from 'node:path';
import { AsyncLocalStorage } from 'node:async_hooks';
import YAML from 'yaml';
import { parse as parseTOML } from 'smol-toml';
import type { ParsedConfig } from './types.js';
import type { FSProvider } from './fs-provider.js';
import { LocalFSProvider } from './local-fs-provider.js';

/** A config file that exists but could not be read or parsed. Without this
 *  signal a corrupted config is indistinguishable from an absent one: adapters
 *  catch the loadConfig throw and skip the file, so the scan silently reports
 *  the agent as clean (or not installed) instead of "couldn't inspect it". */
export interface ConfigLoadError {
  filePath: string;
  stage: 'read' | 'parse';
  message: string;
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

function recordLoadError(error: ConfigLoadError): void {
  loadErrorStore.getStore()?.push(error);
}

/** Missing files are a normal probe outcome, not a load failure. Matches both
 *  node fs errors (`code === 'ENOENT'`) and SnapshotFSProvider's plain Errors
 *  whose message leads with "ENOENT". */
function isFileNotFound(error: unknown): boolean {
  if ((error as NodeJS.ErrnoException | null)?.code === 'ENOENT') return true;
  return error instanceof Error && error.message.startsWith('ENOENT');
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export async function loadConfig(filePath: string, fs?: FSProvider): Promise<ParsedConfig> {
  const provider = fs ?? new LocalFSProvider();

  let raw: string;
  try {
    raw = await provider.readFile(filePath);
  } catch (error) {
    if (!isFileNotFound(error)) {
      recordLoadError({ filePath, stage: 'read', message: errorMessage(error) });
    }
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

  return { raw, format, filePath, data: data === UNPARSEABLE ? {} : data };
}

function detectFormat(ext: string, filePath: string): ParsedConfig['format'] {
  switch (ext) {
    case '.json':
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
      return JSON.parse(raw);
    case 'yaml':
      return YAML.parse(raw) ?? {};
    case 'env':
      return parseEnv(raw);
    case 'toml':
      return parseTOML(raw) as Record<string, unknown>;
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
    const key = trimmed.slice(0, eqIndex).trim();
    let value = trimmed.slice(eqIndex + 1).trim();
    // Strip surrounding quotes
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
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
      return YAML.parse(raw) ?? {};
    } catch {
      try {
        return parseTOML(raw) as Record<string, unknown>;
      } catch {
        return UNPARSEABLE;
      }
    }
  }
}
