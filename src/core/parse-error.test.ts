import { describe, it, expect } from 'vitest';
import YAML from 'yaml';
import { parse as parseToml } from 'smol-toml';
import { parseErrorMessage, scrubParseError } from './parse-error.js';
import { parseYamlSafe } from './yaml-safe.js';
import { parseTomlSafe } from './toml-safe.js';
import { parseJsonLenient } from './jsonc.js';
import { captureConfigLoadErrors, loadConfig } from './config-loader.js';
import { MCPDiscovery } from '../mcp/discovery.js';
import { LocalFSProvider } from './local-fs-provider.js';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const KEY = 'sk-proj-PLANTEDa8Kd93LmQz7Xw2Vb5Nc1QzQz';
const WEAK = 'plantedweakpw';

const BROKEN = {
  yaml: `model:\n  api_key: ${KEY}\n  password: ${WEAK}\n bad: [\n`,
  toml: `[env]\nOPENAI_API_KEY = "${KEY}"\nDB_PASSWORD = "${WEAK}"\nbroken = = 1\n`,
  json: `${KEY}`,
  jsonMid: `{"api_key": "${KEY}", ${WEAK}}`,
};

function thrown(f: () => unknown): Error {
  try {
    f();
  } catch (err) {
    return err as Error;
  }
  throw new Error('did not throw');
}

describe('parseErrorMessage', () => {
  it('drops the yaml code frame and keeps line and column', () => {
    const msg = parseErrorMessage(thrown(() => YAML.parse(BROKEN.yaml)));
    expect(msg).not.toContain(KEY);
    expect(msg).not.toContain(WEAK);
    expect(msg).toMatch(/at line \d+, column \d+$/);
  });

  it('drops the smol-toml code frame and adds line and column', () => {
    const msg = parseErrorMessage(thrown(() => parseToml(BROKEN.toml)));
    expect(msg).toBe('Invalid TOML document: invalid value at line 4, column 10');
  });

  it("drops V8's JSON text snippet", () => {
    for (const text of [BROKEN.json, BROKEN.jsonMid, `{"a": t${KEY}}`]) {
      const msg = parseErrorMessage(thrown(() => JSON.parse(text)));
      expect(msg).not.toMatch(/sk-proj|planted/);
    }
    expect(parseErrorMessage(new SyntaxError(`Unexpected token 's', "${KEY.slice(0, 10)}"... is not valid JSON`)))
      .toBe('not valid JSON');
  });

  it('keeps plain one-line messages', () => {
    expect(parseErrorMessage(new Error('EACCES: permission denied, open \'/x\''))).toBe('EACCES: permission denied, open \'/x\'');
    expect(parseErrorMessage('not a config object')).toBe('not a config object');
  });
});

describe('scrubParseError', () => {
  it('rewrites message, stack and codeblock in place, keeping the class', () => {
    const err = thrown(() => parseToml(BROKEN.toml));
    const cls = err.constructor;
    scrubParseError(err);
    expect(err.constructor).toBe(cls);
    expect(err.message).not.toContain(KEY);
    expect(err.stack).not.toContain(KEY);
    expect(JSON.stringify(err)).not.toContain(KEY);
    expect(err.stack).toMatch(/\n\s+at /);
  });
});

describe('parse helpers throw content-free errors', () => {
  it.each([
    ['parseYamlSafe', () => parseYamlSafe(BROKEN.yaml)],
    ['parseYamlSafe (reject duplicates)', () => parseYamlSafe(BROKEN.yaml, { duplicateKeys: 'reject' })],
    ['parseTomlSafe', () => parseTomlSafe(BROKEN.toml)],
    ['parseJsonLenient', () => parseJsonLenient(BROKEN.jsonMid)],
  ])('%s', (_, f) => {
    const err = thrown(f);
    for (const text of [err.message, err.stack ?? '', JSON.stringify(err)]) {
      expect(text).not.toContain(KEY);
      expect(text).not.toContain(WEAK);
    }
  });
});

async function homeWith(files: Record<string, string>): Promise<string> {
  const home = await mkdtemp(join(tmpdir(), 'vaso-perr-'));
  for (const [rel, content] of Object.entries(files)) {
    await mkdir(join(home, rel, '..'), { recursive: true });
    await writeFile(join(home, rel), content);
  }
  return home;
}

describe('surfaced load errors carry no config content', () => {
  it('CONFIG-LOAD messages from loadConfig', async () => {
    const home = await homeWith({ 'a.yaml': BROKEN.yaml, 'b.toml': BROKEN.toml, 'c.json': BROKEN.jsonMid });
    const fs = new LocalFSProvider();
    const { loadErrors } = await captureConfigLoadErrors(async () => {
      for (const p of ['a.yaml', 'b.toml', 'c.json']) await loadConfig(join(home, p), fs).catch(() => undefined);
    });
    await rm(home, { recursive: true, force: true });
    expect(loadErrors).toHaveLength(3);
    for (const e of loadErrors) {
      expect(e.message).not.toContain(KEY);
      expect(e.message).not.toContain(WEAK);
      // Node 20's JSON.parse gives `at position N`; Node 22+ adds `(line L column C)`
      expect(e.message).toMatch(/line \d+|position \d+/);
    }
  });

  it('vaso mcp discovery load errors', async () => {
    const home = await homeWith({ '.codex/config.toml': BROKEN.toml, '.hermes/config.yaml': BROKEN.yaml });
    const fs = new LocalFSProvider();
    fs.homedir = () => home;
    const result = await new MCPDiscovery(fs).discover();
    await rm(home, { recursive: true, force: true });
    const errors = result.loadErrors ?? [];
    expect(errors.map(e => e.source).sort()).toEqual(expect.arrayContaining([expect.stringMatching(/Codex/), expect.stringMatching(/Hermes/)]));
    for (const e of errors) {
      expect(e.message).not.toContain(KEY);
      expect(e.message).not.toContain(WEAK);
      expect(e.message).toMatch(/at line \d+, column \d+/);
    }
  });
});
