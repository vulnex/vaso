import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { updateEnvFile, updateTomlFile, updateYamlFile, collectWriteNotes } from './config-writer.js';
import { parseTomlSafe } from '../core/toml-safe.js';
import { parseYamlSafe } from '../core/yaml-safe.js';

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'vaso-layout-')); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

function file(name: string, content: string): string {
  const p = join(dir, name);
  writeFileSync(p, content);
  return p;
}

describe('TOML table headers with a trailing comment', () => {
  it('edits in place when the comment holds a "]"', async () => {
    const src = '# top\n[gateway] # see [docs]\nhost = "0.0.0.0" # exposed\nport = 1\n\n[skills]\nopen_skills_enabled = true\n';
    const p = file('c.toml', src);
    await updateTomlFile(p, 'gateway.host', '127.0.0.1');
    expect(readFileSync(p, 'utf8')).toBe(src.replace('"0.0.0.0"', '"127.0.0.1"'));
  });

  it('reads a quoted segment holding "]"', async () => {
    const src = '[agents."a]b"]\nenabled = true # on\n';
    const p = file('c.toml', src);
    await updateTomlFile(p, ['agents', 'a]b', 'enabled'], false);
    expect(readFileSync(p, 'utf8')).toBe('[agents."a]b"]\nenabled = false # on\n');
    expect(parseTomlSafe(readFileSync(p, 'utf8'))).toEqual({ agents: { 'a]b': { enabled: false } } });
  });
});

describe('YAML fixes', () => {
  it('refuses to edit through an alias, with a message that says why', async () => {
    const p = file('a.yaml', 'defaults: &gw\n  bind: lan\ngateway: *gw\n');
    await expect(updateYamlFile(p, 'gateway.bind', 'loopback')).rejects.toThrow(/gateway in .* is a YAML alias \(\*gw\)/);
    expect(readFileSync(p, 'utf8')).toBe('defaults: &gw\n  bind: lan\ngateway: *gw\n');
  });

  it('sets a key next to a merge key (the local key overrides the merged one)', async () => {
    const p = file('m.yaml', 'defaults: &gw\n  bind: lan\ngateway:\n  <<: *gw\n  mode: local\n');
    await updateYamlFile(p, 'gateway.bind', 'loopback');
    expect((parseYamlSafe(readFileSync(p, 'utf8')) as { gateway: { bind: string } }).gateway.bind).toBe('loopback');
  });

  it('changes only the edited scalar: no refolding, flow spacing or quoting changes', async () => {
    const long = 'x'.repeat(120);
    const src = `# sub-agent config\ngateway:\n  bind: 'lan' # was exposed\n  note: "${long}"\ntags: [a,b,  c]\nnum: 0x1f\nyes_str: yes\n`;
    const p = file('f.yaml', src);
    await updateYamlFile(p, 'gateway.bind', 'loopback');
    expect(readFileSync(p, 'utf8')).toBe(src.replace("'lan'", "'loopback'"));
  });

  it('refuses to edit an anchored node an alias elsewhere refers to (scalar or ancestor map)', async () => {
    const scalar = 'gateway:\n  bind: &host lan\nchannels:\n  web:\n    listen: *host\n';
    const p = file('as.yaml', scalar);
    await expect(updateYamlFile(p, 'gateway.bind', 'loopback')).rejects.toThrow(/gateway\.bind in .* is a YAML anchor \(&host\) other keys alias/);
    expect(readFileSync(p, 'utf8')).toBe(scalar);
    const map = 'gateway: &g\n  bind: lan\nbackup: *g\n';
    const q = file('am.yaml', map);
    await expect(updateYamlFile(q, 'gateway.bind', 'loopback')).rejects.toThrow(/gateway in .* is a YAML anchor \(&g\)/);
    await expect(updateYamlFile(q, 'gateway.port', 1)).rejects.toThrow(/YAML anchor/);
    expect(readFileSync(q, 'utf8')).toBe(map);
  });

  it('edits an anchored node no alias refers to', async () => {
    const p = file('an.yaml', 'gateway:\n  bind: &host lan\n');
    await updateYamlFile(p, 'gateway.bind', 'loopback');
    expect(readFileSync(p, 'utf8')).toBe('gateway:\n  bind: &host loopback\n');
  });

  it('adds a missing key as a new line in its block, leaving every other line as it was', async () => {
    const long = 'This is a very long description string that definitely exceeds eighty characters in width for sure yes';
    const src = `# only comment\ngateway:\n  port: 18789 # p\n  tls: {enabled: false}\nmcp:\n  args: ["-y", "pkg"]\n  env: {API_KEY: "\${KEY}"}\nlong: "${long}"\n`;
    const p = file('add.yaml', src);
    await updateYamlFile(p, 'gateway.bind', 'loopback');
    expect(readFileSync(p, 'utf8')).toBe(src.replace('  tls: {enabled: false}\n', '  tls: {enabled: false}\n  bind: loopback\n'));
    // a missing parent too, with the file's indentation, CRLF and no final newline
    const q = file('add2.yaml', 'model:\r\n    name: x\r\n    args: [a,b]');
    await updateYamlFile(q, 'model.limits.max', 5);
    expect(readFileSync(q, 'utf8')).toBe('model:\r\n    name: x\r\n    args: [a,b]\r\n    limits:\r\n        max: 5\r\n');
    // at the root, after a nested block and a trailing comment
    const r = file('add3.yaml', 'a:\n  b: 1 # c\n# tail\n');
    await updateYamlFile(r, 'z', true);
    expect(parseYamlSafe(readFileSync(r, 'utf8'))).toEqual({ a: { b: 1 }, z: true });
    expect(readFileSync(r, 'utf8')).toMatch(/^a:\n  b: 1 # c\n/);
  });

  it('says so when the key can only be added by re-serializing', async () => {
    const p = file('flow.yaml', 'gateway: {port: 1}\nargs: [ "-y" ]\n');
    const { notes } = await collectWriteNotes(() => updateYamlFile(p, 'gateway.bind', 'loopback'));
    expect(parseYamlSafe(readFileSync(p, 'utf8'))).toEqual({ gateway: { port: 1, bind: 'loopback' }, args: ['-y'] });
    expect(notes).toHaveLength(1);
    expect(notes[0]).toMatch(/re-serialized to set gateway\.bind/);
  });

  it('quotes a string that would otherwise read as another type', async () => {
    const p = file('q.yaml', 'mode: off\n');
    await updateYamlFile(p, 'mode', 'true');
    expect(parseYamlSafe(readFileSync(p, 'utf8'))).toEqual({ mode: 'true' });
  });
});

describe('env fixes keep the file\'s line endings and byte-order mark', () => {
  it('keeps CRLF on the rewritten line and the BOM', async () => {
    const p = file('.env', '﻿NODE_ENV=development\r\nOTHER=1\r\n');
    await updateEnvFile(p, 'NODE_ENV', 'production');
    expect(readFileSync(p, 'utf8')).toBe('﻿NODE_ENV=production\r\nOTHER=1\r\n');
  });

  it('ends an inserted line like the rest', async () => {
    const p = file('.env', 'A=1\r\nB=2');
    await updateEnvFile(p, 'C', '3');
    expect(readFileSync(p, 'utf8')).toBe('A=1\r\nB=2\r\nC=3\r\n');
  });

  it('keeps an export prefix and a trailing comment', async () => {
    const p = file('.env', 'export NODE_ENV="development"  # dev box\n');
    await updateEnvFile(p, 'NODE_ENV', 'production');
    expect(readFileSync(p, 'utf8')).toBe('export NODE_ENV=production  # dev box\n');
  });
});
