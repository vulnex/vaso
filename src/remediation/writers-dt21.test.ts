import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { updateJsonFile, updateTomlFile, updateYamlFile } from './config-writer.js';
import { editJsonText } from './json-edit.js';
import { loadConfig } from '../core/config-loader.js';
import { parseTomlSafe } from '../core/toml-safe.js';
import { parseJsonLenient } from '../core/jsonc.js';

// dt21 g8-F18 / g8-F21: TOML integers beyond 2^53 parse; fixes keep comments,
// JSON5 spellings and big integers.

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'vaso-writers-')); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

function file(name: string, content: string): string {
  const p = join(dir, name);
  writeFileSync(p, content);
  return p;
}

describe('TOML integers beyond 2^53 (g8-F18)', () => {
  it('parses i64 max and other out-of-range integers instead of failing the whole config', () => {
    const data = parseTomlSafe('[gateway]\nhost = "0.0.0.0"\nallow_public_bind = true\n[limits]\nmax_bytes = 9223372036854775807\nlist = [1, -9223372036854775808]\n');
    expect(data.gateway).toEqual({ host: '0.0.0.0', allow_public_bind: true });
    expect(typeof (data.limits as Record<string, unknown>).max_bytes).toBe('number');
    expect(() => JSON.stringify(data)).not.toThrow();
  });

  it('loads such a config through loadConfig', async () => {
    const p = file('config.toml', 'max_bytes = 9223372036854775807\n[gateway]\nhost = "0.0.0.0"\n');
    const config = await loadConfig(p);
    expect((config.data.gateway as Record<string, unknown>).host).toBe('0.0.0.0');
  });

  it('keeps the exact value when a fix rewrites the file', async () => {
    const p = file('config.toml', '# keep\nmax_bytes = 9223372036854775807\n[gateway]\nhost = "0.0.0.0"\n');
    await updateTomlFile(p, 'gateway.host', '127.0.0.1');
    expect(readFileSync(p, 'utf-8')).toBe('# keep\nmax_bytes = 9223372036854775807\n[gateway]\nhost = "127.0.0.1"\n');
  });
});

describe('JSON fixes edit the text (g8-F21)', () => {
  it('keeps JSONC comments, JSON5 number spellings and integers beyond 2^53', async () => {
    const src = '{\n  // gateway settings\n  gateway: { bind: "lan", timeoutSeconds: 1e3 },\n  /* ids */\n  "guild": 1098765432109876543,\n  mask: 0x10,\n}\n';
    const p = file('openclaw.json', src);
    await updateJsonFile(p, 'gateway.bind', 'loopback');
    expect(readFileSync(p, 'utf-8')).toBe(src.replace('"lan"', '"loopback"'));
  });

  it('adds a missing key after the last member, keeping a trailing comment on its line', async () => {
    const p = file('a.json', '{\n  "a": 1 // note\n}\n');
    await updateJsonFile(p, 'gateway.host', '127.0.0.1');
    const out = readFileSync(p, 'utf-8');
    expect(out).toBe('{\n  "a": 1, // note\n  "gateway": {\n    "host": "127.0.0.1"\n  }\n}\n');
    expect(parseJsonLenient(out)).toEqual({ a: 1, gateway: { host: '127.0.0.1' } });
  });

  it('fills an empty object, adds to a one-line object and keeps a byte-order mark and trailing commas', () => {
    expect(editJsonText('{\n  "a": {},\n  "b": 2\n}\n', ['a', 'k'], true)).toBe('{\n  "a": {\n    "k": true\n  },\n  "b": 2\n}\n');
    expect(editJsonText('{"a":1,"z":{"q":1}}', ['z', 'w'], false)).toBe('{"a":1,"z":{"q":1, "w": false}}');
    expect(editJsonText('\ufeff{\n\t"a": 1,\n}\n', ['b'], 'x')).toBe('\ufeff{\n\t"a": 1,\n\t"b": "x",\n}\n');
  });

  it('edits the last of repeated keys (the one parsers keep)', () => {
    expect(editJsonText('{"a": 1, "a": 2}', ['a'], 3)).toBe('{"a": 1, "a": 3}');
  });

  it('gives up on documents it cannot follow (the writer then re-serializes)', () => {
    expect(editJsonText('[1, 2]', ['a'], 1)).toBeUndefined();
    expect(editJsonText('{"a": 1', ['a'], 2)).toBeUndefined();
  });
});

describe('YAML fixes keep big integers', () => {
  it('writes integers beyond 2^53 back unchanged', async () => {
    const p = file('c.yaml', '# c\nid: 1098765432109876543\nhex: 0x10\n');
    await updateYamlFile(p, 'gateway.bind', 'loopback');
    expect(readFileSync(p, 'utf-8')).toBe('# c\nid: 1098765432109876543\nhex: 0x10\ngateway:\n  bind: loopback\n');
  });
});

describe('TOML fixes inside an inline table (g8-F21)', () => {
  it('edits the key in place instead of re-serializing the file (comments kept)', async () => {
    const src = '# top\n[agents.main]\nworkspace = { a = 1, unrestricted_filesystem = true } # keep\n\n[other]\nx = 1 # c\n';
    const p = file('config.toml', src);
    await updateTomlFile(p, 'agents.main.workspace.unrestricted_filesystem', false);
    expect(readFileSync(p, 'utf-8')).toBe(src.replace('unrestricted_filesystem = true', 'unrestricted_filesystem = false'));
  });

  it('adds a missing key to the inline table and follows nested inline tables', async () => {
    const p = file('config.toml', 'workspace = { a = 1, inner = { b = "x" } }\n');
    await updateTomlFile(p, 'workspace.c', true);
    await updateTomlFile(p, 'workspace.inner.b', 'y');
    expect(readFileSync(p, 'utf-8')).toBe('workspace = { a = 1, inner = { b = "y" }, c = true }\n');
  });
});

describe('round 2: line endings and JSON5 unicode keys', () => {
  it('inserts CRLF lines into a CRLF file (dt21 g4-R1)', async () => {
    const src = '{\r\n  "agent": {\r\n    "approvalLevel": 2\r\n  }\r\n}\r\n';
    const p = file('config.json', src);
    await updateJsonFile(p, 'http.allowUnapproved', false);
    const out = readFileSync(p, 'utf-8');
    expect(out.replace(/\r\n/g, '')).not.toContain('\n');
    expect(parseJsonLenient(out)).toEqual({ agent: { approvalLevel: 2 }, http: { allowUnapproved: false } });
  });

  it('keeps a trailing comment on a CRLF line when appending after it', () => {
    const out = editJsonText('{\r\n  "a": 1 // note\r\n}\r\n', ['b'], 2)!;
    expect(out).toBe('{\r\n  "a": 1, // note\r\n  "b": 2\r\n}\r\n');
  });

  it('edits in place next to a unicode JSON5 key instead of rewriting the file (dt21 g8-R4)', async () => {
    const src = '{\n  // keep\n  café: 1,\n  id: 1098765432109876543,\n  gateway: { bind: "lan" },\n}\n';
    const p = file('openclaw.json', src);
    await updateJsonFile(p, 'gateway.bind', 'loopback');
    expect(readFileSync(p, 'utf-8')).toBe(src.replace('"lan"', '"loopback"'));
    // and an escaped identifier names the same key
    expect(editJsonText('{ \\u00411: 1 }', ['A1'], 2)).toBe('{ \\u00411: 2 }');
  });
});

describe('round 3: TOML edits in CRLF files (dt21 g5-R2-5)', () => {
  it('keeps CRLF on the edited line and on inserted lines', async () => {
    const src = '# top\r\n[gateway]\r\nhost = "0.0.0.0" # public\r\nallow_public_bind = true\r\n';
    const p = file('config.toml', src);
    await updateTomlFile(p, 'gateway.host', '127.0.0.1');
    await updateTomlFile(p, 'gateway.require_pairing', true);
    await updateTomlFile(p, 'tunnel.tunnel_provider', 'none');
    const out = readFileSync(p, 'utf-8');
    expect(out.replace(/\r\n/g, '')).not.toContain('\n');
    expect(out).toContain('host = "127.0.0.1" # public\r\n');
    expect(parseTomlSafe(out)).toEqual({ gateway: { host: '127.0.0.1', allow_public_bind: true, require_pairing: true }, tunnel: { tunnel_provider: 'none' } });
  });

  it('leaves a mixed-ending file\'s bare LFs alone', async () => {
    const p = file('mixed.toml', 'a = 1\r\nb = 2\n');
    await updateTomlFile(p, 'b', 3);
    expect(readFileSync(p, 'utf-8')).toBe('a = 1\r\nb = 3\n');
  });
});

describe('YAML fix refusals read as plain sentences', () => {
  it('names the parent that is not a mapping', async () => {
    const nul = file('a.yaml', 'gateway:\nother: 1\n');
    await expect(updateYamlFile(nul, 'gateway.tls.enabled', true)).rejects.toThrow(/gateway in .* is empty \(null\), not a mapping — there is nowhere to set tls\.enabled under it/);
    const seq = file('b.yaml', 'gateway:\n  - tls\n');
    await expect(updateYamlFile(seq, 'gateway.tls.enabled', true)).rejects.toThrow(/gateway in .* is a list, not a mapping/);
    const scalar = file('c.yaml', 'gateway:\n  tls: yes-please\n');
    await expect(updateYamlFile(scalar, 'gateway.tls.enabled', true)).rejects.toThrow(/gateway\.tls in .* is a single value, not a mapping/);
    for (const p of [nul, seq, scalar]) {
      await expect(updateYamlFile(p, 'gateway.tls.enabled', true)).rejects.not.toThrow(/Remaining path|Expected/);
    }
  });

  it('says a file with YAML errors is not rewritten, without quoting it', async () => {
    const p = file('d.yaml', 'token: sk-ant-api03-AAAAAAAAAAAAAAAA\ntoken: sk-ant-api03-BBBBBBBBBBBBBBBB\n');
    await expect(updateYamlFile(p, 'gateway.tls.enabled', true)).rejects.toThrow(/has YAML errors \(a duplicate key\) — vaso won't rewrite it; set gateway\.tls\.enabled by hand/);
    await expect(updateYamlFile(p, 'gateway.tls.enabled', true)).rejects.not.toThrow(/sk-ant/);
  });
});
