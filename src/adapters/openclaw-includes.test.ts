import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm, symlink, chmod, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { captureConfigLoadErrors } from '../core/config-loader.js';
import { includeRootsFromEnv, loadOpenclawConfig, mergeIncluded } from './openclaw-includes.js';

let root: string;
let dir: string;
const fs = new LocalFSProvider();

async function put(rel: string, content: string): Promise<string> {
  const p = join(dir, rel);
  await mkdir(join(p, '..'), { recursive: true });
  await writeFile(p, content);
  return p;
}

async function load(main: string, roots: string[] = []) {
  const { result, loadErrors } = await captureConfigLoadErrors(() => loadOpenclawConfig(join(dir, main), fs, roots));
  return { data: result.data, loadErrors };
}

beforeEach(async () => {
  root = await realpath(await mkdtemp(join(tmpdir(), 'vaso-oc-inc-')));
  dir = join(root, '.openclaw');
  await mkdir(dir);
});

afterEach(async () => {
  await chmod(dir, 0o755).catch(() => {});
  await rm(root, { recursive: true, force: true });
});

describe('OpenClaw $include', () => {
  it('a single include replaces the object holding it (the gateway OpenClaw runs)', async () => {
    await put('gateway.json5', '{ mode: "local", bind: "lan", auth: { mode: "none" } }');
    await put('openclaw.json', '// json5\n{ gateway: { $include: "./gateway.json5" } }');
    const { data, loadErrors } = await load('openclaw.json');
    expect(data.gateway).toEqual({ mode: 'local', bind: 'lan', auth: { mode: 'none' } });
    expect(loadErrors).toEqual([]);
  });

  it('leaves a config without directives untouched', async () => {
    await put('openclaw.json', '{ "gateway": { "bind": "loopback" } }');
    expect((await load('openclaw.json')).data).toEqual({ gateway: { bind: 'loopback' } });
  });

  it('deep-merges an include list in order and lets sibling keys override', async () => {
    await put('a.json5', '{ bind: "lan", tools: ["x"], auth: { mode: "token" } }');
    await put('b.json5', '{ bind: "loopback", tools: ["y"] }');
    await put('openclaw.json', '{ gateway: { $include: ["./a.json5", "./b.json5"], auth: { mode: "none" } } }');
    const { data } = await load('openclaw.json');
    expect(data.gateway).toEqual({ bind: 'loopback', tools: ['x', 'y'], auth: { mode: 'none' } });
  });

  it('resolves nested includes relative to the including file, and inside arrays', async () => {
    await put('parts/agents.json5', '{ list: [{ $include: "./one.json5" }] }');
    await put('parts/one.json5', '{ id: "main", sandbox: { mode: "off" } }');
    await put('openclaw.json', '{ agents: { $include: "./parts/agents.json5" } }');
    const { data, loadErrors } = await load('openclaw.json');
    expect(data.agents).toEqual({ list: [{ id: 'main', sandbox: { mode: 'off' } }] });
    expect(loadErrors).toEqual([]);
  });

  it('a root-level include merges with the rest of the file', async () => {
    await put('base.json5', '{ gateway: { bind: "lan", port: 1 } }');
    await put('openclaw.json', '{ $include: "./base.json5", gateway: { port: 2 } }');
    expect((await load('openclaw.json')).data).toEqual({ gateway: { bind: 'lan', port: 2 } });
  });

  it('never reads outside the config directory: ../ and absolute paths are rejected', async () => {
    await writeFile(join(root, 'outside.json5'), '{ bind: "lan" }');
    await put('openclaw.json', `{ gateway: { $include: "../outside.json5" }, hooks: { $include: "${join(root, 'outside.json5')}" } }`);
    const { data, loadErrors } = await load('openclaw.json');
    expect(data.gateway).toEqual({});
    expect(data.hooks).toEqual({});
    expect(loadErrors).toHaveLength(1); // one finding per config file and stage
    expect(loadErrors[0].message).toMatch(/escapes the config directory/);
  });

  it('rejects a symlink inside the directory that points outside it', async () => {
    await writeFile(join(root, 'secret.json5'), '{ bind: "lan" }');
    await symlink(join(root, 'secret.json5'), join(dir, 'link.json5'));
    await put('openclaw.json', '{ gateway: { $include: "./link.json5" } }');
    const { data, loadErrors } = await load('openclaw.json');
    expect(data.gateway).toEqual({});
    expect(loadErrors[0].message).toMatch(/through a symlink/);
  });

  it('OPENCLAW_INCLUDE_ROOTS admits another directory', async () => {
    const shared = join(root, 'shared');
    await mkdir(shared);
    await writeFile(join(shared, 'gw.json5'), '{ bind: "lan" }');
    await put('openclaw.json', `{ gateway: { $include: "${join(shared, 'gw.json5')}" } }`);
    const { data, loadErrors } = await load('openclaw.json', includeRootsFromEnv(`~/shared`, root));
    expect(data.gateway).toEqual({ bind: 'lan' });
    expect(loadErrors).toEqual([]);
  });

  it('stops at a circular include', async () => {
    await put('a.json5', '{ $include: "./b.json5" }');
    await put('b.json5', '{ $include: "./a.json5" }');
    await put('openclaw.json', '{ gateway: { $include: "./a.json5" } }');
    const { loadErrors } = await load('openclaw.json');
    expect(loadErrors[0].message).toMatch(/circular \$include/);
  });

  it('stops nesting after 10 levels', async () => {
    for (let i = 0; i < 12; i++) await put(`n${i}.json5`, `{ $include: "./n${i + 1}.json5" }`);
    await put('n12.json5', '{ bind: "lan" }');
    await put('openclaw.json', '{ gateway: { $include: "./n0.json5" } }');
    const { loadErrors } = await load('openclaw.json');
    expect(loadErrors[0].message).toMatch(/deeper than 10/);
  });

  it('bounds a fan-out that is not circular', async () => {
    const fan = (next: string) => `{ $include: [${Array(4).fill(`"./${next}"`).join(',')}] }`;
    for (let i = 0; i < 8; i++) await put(`f${i}.json5`, fan(`f${i + 1}.json5`));
    await put('f8.json5', '{ x: 1 }');
    await put('openclaw.json', '{ gateway: { $include: "./f0.json5" } }');
    const { loadErrors } = await load('openclaw.json');
    expect(loadErrors[0].message).toMatch(/more than 200 \$include loads/);
  });

  it('reports a missing include as CONFIG-LOAD (OpenClaw rejects the config)', async () => {
    await put('openclaw.json', '{ gateway: { $include: "./nope.json5" } }');
    const { loadErrors } = await load('openclaw.json');
    expect(loadErrors).toEqual([expect.objectContaining({ filePath: join(dir, 'nope.json5'), stage: 'read', message: expect.stringMatching(/file not found/) })]);
  });

  it.skipIf(process.getuid?.() === 0 || process.platform === 'win32')('reports an unreadable include through the shared loader', async () => {
    const p = await put('gw.json5', '{ bind: "lan" }');
    await chmod(p, 0o000);
    await put('openclaw.json', '{ gateway: { $include: "./gw.json5" } }');
    const { loadErrors } = await load('openclaw.json');
    expect(loadErrors).toEqual([expect.objectContaining({ filePath: p, stage: 'read' })]);
  });

  it('merges objects recursively, concatenates arrays and skips prototype keys', () => {
    expect(mergeIncluded({ a: { b: 1 }, l: [1] }, { a: { c: 2 }, l: [2], x: 'y' })).toEqual({ a: { b: 1, c: 2 }, l: [1, 2], x: 'y' });
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    mergeIncluded({}, JSON.parse('{"__proto__": {"polluted": true}}'));
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });
});
