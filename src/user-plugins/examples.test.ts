import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const examples = join(__dirname, '..', '..', 'examples', 'plugins');

describe('examples/plugins/env-hygiene-check.mjs', () => {
  it('flags development settings in JSON as well as .env files', async () => {
    const mod = await import(pathToFileURL(join(examples, 'env-hygiene-check.mjs')).href);
    let check: { run(ctx: unknown): Promise<{ passed: boolean; evidence?: { file: string }[] }> } | undefined;
    mod.default.register({ registerCheck: (c: typeof check) => { check = c; }, registerAdapter() {}, registerReporter() {} });
    const configs = [
      { filePath: '/a/config.json', raw: '{\n  "NODE_ENV": "development"\n}', data: {} },
      { filePath: '/a/.env', raw: 'DEBUG=true\n# VERBOSE=true\n', data: {} },
    ];
    const result = await check!.run({ configs });
    expect(result.passed).toBe(false);
    expect(result.evidence?.map(e => e.file).sort()).toEqual(['/a/.env', '/a/config.json']);
  });
});
