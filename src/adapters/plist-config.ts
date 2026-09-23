import * as plist from 'plist';
import type { ParsedConfig } from '../core/types.js';
import type { FSProvider } from '../core/fs-provider.js';

/**
 * Load a macOS plist (binary or XML) as a ParsedConfig via `plutil -convert
 * xml1 -o -`, mirroring the chatgpt-desktop adapter's approach so both local
 * and snapshot/SSH transports work (the probe captures plutil stdout; raw
 * binary plist bytes would be mangled by the JSON wire format). Returns
 * undefined when the file is absent, unreadable, or not a dictionary.
 */
export async function loadPlistAsConfig(filePath: string, fs: FSProvider): Promise<ParsedConfig | undefined> {
  if (!(await fs.access(filePath))) return undefined;
  try {
    const result = await fs.exec('plutil', ['-convert', 'xml1', '-o', '-', filePath], { timeout: 3000 });
    if (result.exitCode !== 0 || !result.stdout) return undefined;
    const parsed = plist.parse(result.stdout) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined;
    const data = normalizeValue(parsed) as Record<string, unknown>;
    return { raw: JSON.stringify(data), format: 'json', filePath, data };
  } catch {
    return undefined;
  }
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
