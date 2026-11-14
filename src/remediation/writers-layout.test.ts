import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { updateEnvFile, updateTomlFile, updateYamlFile } from './config-writer.js';
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
