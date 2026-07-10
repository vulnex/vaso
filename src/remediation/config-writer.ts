import { readFile, writeFile, chmod } from 'node:fs/promises';
import YAML from 'yaml';
import { parse as parseTOML, stringify as stringifyTOML } from 'smol-toml';
import type { FixResult, ParsedConfig } from '../core/types.js';
import { setNestedValue } from '../core/utils.js';

/**
 * Update or insert a key=value pair in a .env file.
 * Preserves comments and line ordering.
 */
export async function updateEnvFile(filePath: string, key: string, value: string): Promise<void> {
  const content = await readFile(filePath, 'utf-8');
  const lines = content.split('\n');
  let found = false;

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) continue;
    const lineKey = trimmed.slice(0, eqIndex).trim();
    if (lineKey === key) {
      lines[i] = `${key}=${value}`;
      found = true;
      break;
    }
  }

  if (!found) {
    // Insert before trailing blank lines
    let insertIndex = lines.length;
    while (insertIndex > 0 && lines[insertIndex - 1].trim() === '') {
      insertIndex--;
    }
    lines.splice(insertIndex, 0, `${key}=${value}`);
  }

  await writeFile(filePath, lines.join('\n'), 'utf-8');
}

/**
 * Update a nested value in a JSON file, detecting and preserving indentation.
 */
export async function updateJsonFile(filePath: string, keyPath: string, value: unknown): Promise<void> {
  const content = await readFile(filePath, 'utf-8');
  const obj = JSON.parse(content);

  // Detect indentation from the file
  const indentMatch = content.match(/^(\s+)/m);
  const indent = indentMatch ? indentMatch[1].length : 2;

  setNestedValue(obj, keyPath, value);
  await writeFile(filePath, JSON.stringify(obj, null, indent) + '\n', 'utf-8');
}

/**
 * Update a nested value in a YAML file using Document API to preserve comments and structure.
 */
export async function updateYamlFile(filePath: string, keyPath: string, value: unknown): Promise<void> {
  const content = await readFile(filePath, 'utf-8');
  const doc = YAML.parseDocument(content);
  const keys = keyPath.split('.');
  doc.setIn(keys, value);
  await writeFile(filePath, doc.toString(), 'utf-8');
}

/**
 * Update a nested value in a TOML file using smol-toml parse/stringify.
 */
export async function updateTomlFile(filePath: string, keyPath: string, value: unknown): Promise<void> {
  const content = await readFile(filePath, 'utf-8');
  const obj = parseTOML(content) as Record<string, unknown>;
  setNestedValue(obj, keyPath, value);
  await writeFile(filePath, stringifyTOML(obj) + '\n', 'utf-8');
}

/**
 * Set file permissions (chmod). Only effective on darwin/linux.
 */
export async function chmodFile(filePath: string, mode: number): Promise<void> {
  await chmod(filePath, mode);
}

/**
 * Dispatcher: route to the correct writer based on config format.
 * For env files, keyPath should be the flat env var name (e.g., 'HTTP_HOST').
 * For json/yaml/toml files, keyPath is dot-separated (e.g., 'gateway.host').
 */
export async function updateConfigValue(config: ParsedConfig, keyPath: string, value: unknown): Promise<void> {
  switch (config.format) {
    case 'env':
      await updateEnvFile(config.filePath, keyPath, String(value));
      break;
    case 'json':
      await updateJsonFile(config.filePath, keyPath, value);
      break;
    case 'yaml':
      await updateYamlFile(config.filePath, keyPath, value);
      break;
    case 'toml':
      await updateTomlFile(config.filePath, keyPath, value);
      break;
    default:
      throw new Error(`Cannot write to config format: ${config.format}`);
  }
}

/**
 * Declarative one-setting fix: what to write, expressed per config dialect.
 * `env` names the flat variable for .env files; `path` the dot-separated key
 * for json/yaml/toml. Omitting one marks that dialect as unsupported for the
 * fix, so those config files are skipped rather than written badly.
 */
export interface FixUpdateSpec {
  checkId: string;
  /** Flat variable name for env-format configs. Omit → env files are skipped. */
  env?: string;
  /** Dot-separated key path for json/yaml/toml configs. Omit → structured files are skipped. */
  path?: string;
  /** Value to write (structured formats; env too unless envValue is given). */
  value: unknown;
  /** Env-file value override for values whose String() form is wrong (e.g. arrays as CSV). */
  envValue?: string;
  /** Success message for the FixResult. */
  message: string;
  /** Not-applied message when no compatible config file exists. */
  noConfigMessage?: string;
}

/**
 * The fix() body shared by most single-setting remediations: walk the
 * installation's config files, write the setting into the first one whose
 * format the spec covers, and report applied/not-applied. Replaces the
 * per-format if/ternary dispatch that used to be copied into every fix.
 */
export async function fixFirstConfig(configs: ParsedConfig[], spec: FixUpdateSpec): Promise<FixResult> {
  for (const config of configs) {
    if (config.format === 'env') {
      if (spec.env === undefined) continue;
      await updateEnvFile(config.filePath, spec.env, spec.envValue ?? String(spec.value));
    } else if (config.format === 'json' || config.format === 'yaml' || config.format === 'toml') {
      if (spec.path === undefined) continue;
      await updateConfigValue(config, spec.path, spec.value);
    } else {
      continue; // unknown format — nothing safe to write
    }
    return { checkId: spec.checkId, applied: true, message: spec.message };
  }
  return {
    checkId: spec.checkId,
    applied: false,
    message: spec.noConfigMessage ?? 'No compatible config file found',
  };
}
