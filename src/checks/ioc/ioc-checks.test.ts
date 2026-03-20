import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { ScanContext, AgentInstallation } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { ioc007 } from './ioc-007-binary-patterns.js';
import { ioc008 } from './ioc-008-virustotal.js';

function makeContext(skillsDir?: string): ScanContext {
  const installation: AgentInstallation = {
    agent: 'openclaw',
    installDir: skillsDir ?? '/tmp/nonexistent',
    configFiles: [],
    skillsDir,
  };
  return { installation, configs: [], platform: 'darwin', fs: new LocalFSProvider() };
}

describe('IOC-007: Binary Pattern Match', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'vaso-ioc007-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('passes when no skills directory', async () => {
    const result = await ioc007.run(makeContext(undefined));
    expect(result.passed).toBe(true);
  });

  it('passes with normal JS file', async () => {
    await writeFile(join(tempDir, 'normal.js'), 'console.log("hello world");');
    const result = await ioc007.run(makeContext(tempDir));
    expect(result.passed).toBe(true);
  });

  it('fails when file contains ELF magic bytes', async () => {
    const buf = Buffer.concat([
      Buffer.from([0x7f, 0x45, 0x4c, 0x46]), // ELF magic
      Buffer.from('// rest of js file'),
    ]);
    await writeFile(join(tempDir, 'suspicious.js'), buf);

    const result = await ioc007.run(makeContext(tempDir));
    expect(result.passed).toBe(false);
    expect(result.evidence).toBeDefined();
    expect(result.evidence![0].detail).toContain('ELF binary');
  });

  it('fails when file contains packed JS eval wrapper', async () => {
    await writeFile(join(tempDir, 'packed.js'), 'eval(function(p,a,c,k,e,d){return "malicious"}())');

    const result = await ioc007.run(makeContext(tempDir));
    expect(result.passed).toBe(false);
    expect(result.evidence).toBeDefined();
    expect(result.evidence![0].detail).toContain('Packed JS eval wrapper');
  });
});

describe('IOC-008: VirusTotal Cross-Reference', () => {
  it('passes with skipped message when no API key', async () => {
    const origKey = process.env['VIRUSTOTAL_API_KEY'];
    delete process.env['VIRUSTOTAL_API_KEY'];

    try {
      const result = await ioc008.run(makeContext('/tmp/some-dir'));
      expect(result.passed).toBe(true);
      expect(result.message).toContain('skipped');
    } finally {
      if (origKey !== undefined) {
        process.env['VIRUSTOTAL_API_KEY'] = origKey;
      }
    }
  });

  it('passes when no skills directory (with API key)', async () => {
    const origKey = process.env['VIRUSTOTAL_API_KEY'];
    process.env['VIRUSTOTAL_API_KEY'] = 'test-key';

    try {
      const result = await ioc008.run(makeContext(undefined));
      expect(result.passed).toBe(true);
    } finally {
      if (origKey !== undefined) {
        process.env['VIRUSTOTAL_API_KEY'] = origKey;
      } else {
        delete process.env['VIRUSTOTAL_API_KEY'];
      }
    }
  });
});
