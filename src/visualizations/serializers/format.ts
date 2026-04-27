import { stringify as tomlStringify } from 'smol-toml';
import { stringify as yamlStringify } from 'yaml';

export type VisFormat = 'toml' | 'json' | 'yaml';

export const VIS_FORMAT_EXTENSIONS: Record<VisFormat, string> = {
  toml: 'toml',
  json: 'json',
  yaml: 'yaml',
};

export function isValidVisFormat(value: string): value is VisFormat {
  return value === 'toml' || value === 'json' || value === 'yaml';
}

export function serialize(shape: unknown, format: VisFormat): string {
  if (format === 'json') return JSON.stringify(shape, null, 2) + '\n';
  if (format === 'yaml') return yamlStringify(shape);
  return tomlStringify(shape as Record<string, unknown>);
}
