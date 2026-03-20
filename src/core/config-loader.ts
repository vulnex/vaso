import { extname } from 'node:path';
import YAML from 'yaml';
import { parse as parseTOML } from 'smol-toml';
import type { ParsedConfig } from './types.js';
import type { FSProvider } from './fs-provider.js';
import { LocalFSProvider } from './local-fs-provider.js';

export async function loadConfig(filePath: string, fs?: FSProvider): Promise<ParsedConfig> {
  const provider = fs ?? new LocalFSProvider();
  const raw = await provider.readFile(filePath);
  const ext = extname(filePath).toLowerCase();
  const format = detectFormat(ext, filePath);
  const data = parseContent(raw, format);

  return { raw, format, filePath, data };
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
        return {};
      }
    }
  }
}
