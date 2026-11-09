import * as plist from 'plist';
import type { ParsedConfig } from '../core/types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { recordConfigLoadFailure, recordLoadError } from '../core/config-loader.js';
import { pathPresent } from './load-if-present.js';

/**
 * Load a macOS plist (binary or XML) as a ParsedConfig via `plutil -convert
 * xml1 -o -`, mirroring the chatgpt-desktop adapter's approach so both local
 * and snapshot/SSH transports work (the probe captures plutil stdout; raw
 * binary plist bytes would be mangled by the JSON wire format). Returns
 * undefined when the file is absent, unreadable, or not a dictionary — the
 * last two recorded as CONFIG-LOAD (see readPlist).
 */
export async function loadPlistAsConfig(filePath: string, fs: FSProvider): Promise<ParsedConfig | undefined> {
  const parsed = await readPlist(filePath, fs);
  if (!parsed) return undefined;
  const data = normalizeValue(parsed) as Record<string, unknown>;
  return { raw: JSON.stringify(data), format: 'json', filePath, data };
}

/**
 * A plist's top-level dictionary through plutil, or undefined. A plist that
 * is there but plutil can't open (unreadable, a directory) or that isn't a
 * dictionary is recorded as a load failure, so it surfaces as CONFIG-LOAD
 * instead of reading as "no preferences set". A command the snapshot didn't
 * collect (exit 127) is not a failure: nothing was learned about the file.
 */
export async function readPlist(filePath: string, fs: FSProvider): Promise<Record<string, unknown> | undefined> {
  if (!(await pathPresent(filePath, fs))) return undefined;
  let result;
  try {
    result = await fs.exec('plutil', ['-convert', 'xml1', '-o', '-', filePath], { timeout: 3000 });
  } catch (err) {
    if ((err as NodeJS.ErrnoException | null)?.code !== 'ENOENT') recordConfigLoadFailure(filePath, 'read', err);
    return undefined;
  }
  if (result.exitCode === 127) return undefined;
  if (result.exitCode !== 0) {
    // plutil names the failure on either stream ("couldn't be opened because
    // you don't have permission", "Property List error: …")
    const message = (result.stderr || result.stdout).trim() || `plutil exited with ${result.exitCode}`;
    const stage = /couldn.t be opened|permission|no such file/i.test(message) ? 'read' : 'parse';
    recordLoadError({ filePath, stage, message });
    return undefined;
  }
  if (!result.stdout) return undefined;
  let parsed: unknown;
  try {
    parsed = plist.parse(result.stdout) as unknown;
  } catch (err) {
    recordConfigLoadFailure(filePath, 'parse', err);
    return undefined;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    recordLoadError({ filePath, stage: 'parse', message: `Top-level value is ${Array.isArray(parsed) ? 'an array' : parsed === null || parsed === undefined ? 'empty' : `a ${typeof parsed}`}, not a dictionary` });
    return undefined;
  }
  return parsed as Record<string, unknown>;
}

function normalizeValue(value: unknown): unknown {
  if (value instanceof Date) return value.toISOString();
  if (Buffer.isBuffer(value)) return value.toString('base64');
  if (Array.isArray(value)) return value.map(normalizeValue);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = normalizeValue(v);
    }
    return out;
  }
  return value;
}
