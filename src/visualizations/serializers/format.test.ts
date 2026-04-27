import { describe, it, expect } from 'vitest';
import { serialize, isValidVisFormat, VIS_FORMAT_EXTENSIONS } from './format.js';
import { parse as parseToml } from 'smol-toml';
import { parse as parseYaml } from 'yaml';

describe('serialize', () => {
  const shape = {
    title: 'Sample',
    items: [{ id: 'a', label: 'A' }, { id: 'b', label: 'B' }],
    meta: { version: '1.0' },
  };

  it('produces valid JSON that round-trips', () => {
    const out = serialize(shape, 'json');
    expect(JSON.parse(out)).toEqual(shape);
  });

  it('produces valid YAML that round-trips', () => {
    const out = serialize(shape, 'yaml');
    expect(parseYaml(out)).toEqual(shape);
  });

  it('produces valid TOML that round-trips', () => {
    const out = serialize(shape, 'toml');
    expect(parseToml(out)).toEqual(shape);
  });
});

describe('isValidVisFormat', () => {
  it('accepts toml/json/yaml', () => {
    expect(isValidVisFormat('toml')).toBe(true);
    expect(isValidVisFormat('json')).toBe(true);
    expect(isValidVisFormat('yaml')).toBe(true);
  });

  it('rejects others', () => {
    expect(isValidVisFormat('xml')).toBe(false);
    expect(isValidVisFormat('')).toBe(false);
  });
});

describe('VIS_FORMAT_EXTENSIONS', () => {
  it('uses the format name as the extension', () => {
    expect(VIS_FORMAT_EXTENSIONS).toEqual({ toml: 'toml', json: 'json', yaml: 'yaml' });
  });
});
