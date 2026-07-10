import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { ScanContext, AgentInstallation, ParsedConfig } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { ioc001 } from './ioc-001-c2-ips.js';
import { ioc002 } from './ioc-002-malicious-domains.js';
import { ioc003 } from './ioc-003-file-hash.js';
import { ioc004 } from './ioc-004-malicious-publishers.js';
import { ioc005 } from './ioc-005-typosquatting.js';
import { ioc006 } from './ioc-006-skill-name-patterns.js';
import { ioc007 } from './ioc-007-binary-patterns.js';
import { ioc008 } from './ioc-008-virustotal.js';

function makeContext(skillsDir?: string, configs: ParsedConfig[] = []): ScanContext {
  const installation: AgentInstallation = {
    agent: 'openclaw',
    installDir: skillsDir ?? '/tmp/nonexistent',
    configFiles: [],
    skillsDir,
  };
  return { installation, configs, platform: 'darwin', fs: new LocalFSProvider() };
}

function configWithRaw(raw: string): ParsedConfig {
  return { raw, format: 'unknown', filePath: '/tmp/fake.config', data: {} };
}

describe('IOC-001: C2 IP Detection', () => {
  // 185.199.228.220 is in the bundled C2 IP list.
  const C2_IP = '185.199.228.220';

  it('detects exact C2 IP in a config raw block', async () => {
    const ctx = makeContext(undefined, [
      configWithRaw(`upstream = "${C2_IP}:443"`),
    ]);
    const result = await ioc001.run(ctx);
    expect(result.passed).toBe(false);
    expect(result.evidence!.some(e => e.detail?.includes(C2_IP))).toBe(true);
  });

  it('does not match an IP that is a substring of a longer numeric run', async () => {
    // 185.199.228.220 is a substring inside 185.199.228.2200 and 1185.199.228.220.
    const ctx = makeContext(undefined, [
      configWithRaw(`bogus_a = "1${C2_IP}"\nbogus_b = "${C2_IP}0"`),
    ]);
    const result = await ioc001.run(ctx);
    expect(result.passed).toBe(true);
  });

  it('does not match an IP that is followed by another octet', async () => {
    const ctx = makeContext(undefined, [
      configWithRaw(`bogus = "${C2_IP}.5"`),
    ]);
    const result = await ioc001.run(ctx);
    expect(result.passed).toBe(true);
  });

  it('matches a C2 IP at port boundary, end of line, and inside a URL', async () => {
    const ctx = makeContext(undefined, [
      configWithRaw([
        `host_port = "${C2_IP}:8080"`,
        `host_alone = "${C2_IP}"`,
        `host_url = "https://${C2_IP}/path"`,
      ].join('\n')),
    ]);
    const result = await ioc001.run(ctx);
    expect(result.passed).toBe(false);
    expect(result.evidence!.length).toBe(3);
  });
});

describe('IOC-002: Malicious Domains', () => {
  // clawhavoc.io is in the bundled malicious domain list.
  const DOMAIN = 'clawhavoc.io';

  it('detects exact domain in a config raw block', async () => {
    const ctx = makeContext(undefined, [
      configWithRaw(`endpoint = "https://${DOMAIN}/api"`),
    ]);
    const result = await ioc002.run(ctx);
    expect(result.passed).toBe(false);
    expect(result.evidence!.some(e => e.detail?.includes(DOMAIN))).toBe(true);
  });

  it('matches subdomain of a malicious domain', async () => {
    const ctx = makeContext(undefined, [
      configWithRaw(`endpoint = "https://bad.${DOMAIN}/exfil"`),
    ]);
    const result = await ioc002.run(ctx);
    expect(result.passed).toBe(false);
  });

  it('does not match a domain that is a left-substring of a different label', async () => {
    // not-clawhavoc.io is a different registration; should not match.
    const ctx = makeContext(undefined, [
      configWithRaw(`endpoint = "https://not-${DOMAIN}/safe"`),
    ]);
    const result = await ioc002.run(ctx);
    expect(result.passed).toBe(true);
  });

  it('does not match a domain whose suffix continues past the IOC TLD', async () => {
    // clawhavoc.iom is a different registration (.iom is a typo TLD).
    const ctx = makeContext(undefined, [
      configWithRaw(`endpoint = "https://${DOMAIN}m/safe"`),
    ]);
    const result = await ioc002.run(ctx);
    expect(result.passed).toBe(true);
  });

  it('does not match a domain whose IOC name is followed by another label', async () => {
    // clawhavoc.io.cn is a different domain hierarchy.
    const ctx = makeContext(undefined, [
      configWithRaw(`endpoint = "https://${DOMAIN}.cn/safe"`),
    ]);
    const result = await ioc002.run(ctx);
    expect(result.passed).toBe(true);
  });

  it('matches case-insensitively', async () => {
    const ctx = makeContext(undefined, [
      configWithRaw(`endpoint = "https://ClawHavoc.IO/api"`),
    ]);
    const result = await ioc002.run(ctx);
    expect(result.passed).toBe(false);
  });
});

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

  // ----- Negative false-positive fixtures -----

  it('passes for ordinary eval() usage that is not the packed-wrapper signature', async () => {
    await writeFile(join(tempDir, 'eval.js'), `
function evaluate(expr) {
  return eval(expr);
}
function reduce(arr) {
  return arr.reduce((a, b) => a + b, 0);
}
`);
    const result = await ioc007.run(makeContext(tempDir));
    expect(result.passed).toBe(true);
  });

  it('passes for high-entropy base64-looking strings without binary magic', async () => {
    const fakeJwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
      'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.' +
      'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    await writeFile(join(tempDir, 'token.js'), `const TOKEN = '${fakeJwt}';\nmodule.exports = { TOKEN };`);
    const result = await ioc007.run(makeContext(tempDir));
    expect(result.passed).toBe(true);
  });

  it('passes for escaped \\x00 in string literals (not real NUL bytes)', async () => {
    const escaped = '\\x00'.repeat(40);
    await writeFile(join(tempDir, 'escapes.js'), `const padding = "${escaped}";`);
    const result = await ioc007.run(makeContext(tempDir));
    expect(result.passed).toBe(true);
  });

  // ----- Offset-0 anchoring regression coverage -----

  it('passes when "MZ" appears mid-file inside an identifier', async () => {
    await writeFile(
      join(tempDir, 'mz-mid.js'),
      'function xMZx() { return 1; }\nconst MZmax = 100;\n',
    );
    const result = await ioc007.run(makeContext(tempDir));
    expect(result.passed).toBe(true);
  });

  it('fails when PE/DOS "MZ" magic is at file offset 0', async () => {
    const buf = Buffer.concat([
      Buffer.from([0x4d, 0x5a]),
      Buffer.from('// rest of fake js'),
    ]);
    await writeFile(join(tempDir, 'pe-magic.js'), buf);
    const result = await ioc007.run(makeContext(tempDir));
    expect(result.passed).toBe(false);
    expect(result.evidence![0].detail).toContain('PE/DOS executable');
  });

  it('passes when ELF magic appears mid-file but not at offset 0', async () => {
    const buf = Buffer.concat([
      Buffer.from('// leading comment\n'),
      Buffer.from([0x7f, 0x45, 0x4c, 0x46]),
      Buffer.from('\n// trailing content'),
    ]);
    await writeFile(join(tempDir, 'elf-mid.js'), buf);
    const result = await ioc007.run(makeContext(tempDir));
    expect(result.passed).toBe(true);
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

describe('IOC-003: File Hash Match', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'vaso-ioc003-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('passes when no skills directory', async () => {
    const result = await ioc003.run(makeContext(undefined));
    expect(result.passed).toBe(true);
  });

  it('flags a file whose SHA-256 matches a bundled malicious hash', async () => {
    // The empty-file SHA-256 (e3b0c44...855) is in the bundled FILE_HASHES list.
    await writeFile(join(tempDir, 'empty.js'), '');
    const result = await ioc003.run(makeContext(tempDir));
    expect(result.passed).toBe(false);
    expect(result.evidence![0].detail).toContain('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  it('passes for files with non-listed hashes', async () => {
    await writeFile(join(tempDir, 'benign.js'), 'console.log("hello");\n');
    const result = await ioc003.run(makeContext(tempDir));
    expect(result.passed).toBe(true);
  });
});

describe('IOC-004: Malicious Publishers', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'vaso-ioc004-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('passes when no skills directory', async () => {
    const result = await ioc004.run(makeContext(undefined));
    expect(result.passed).toBe(true);
  });

  it('flags a skill whose package.json author matches a malicious publisher', async () => {
    const skillDir = join(tempDir, 'evil-skill');
    await mkdir(skillDir, { recursive: true });
    await writeFile(
      join(skillDir, 'package.json'),
      JSON.stringify({ name: 'evil-skill', author: 'clawhavoc' }),
    );
    const result = await ioc004.run(makeContext(tempDir));
    expect(result.passed).toBe(false);
    expect(result.evidence![0].detail).toContain('clawhavoc');
  });

  it('passes for skills with benign publishers', async () => {
    const skillDir = join(tempDir, 'good-skill');
    await mkdir(skillDir, { recursive: true });
    await writeFile(
      join(skillDir, 'package.json'),
      JSON.stringify({ name: 'good-skill', author: { name: 'Acme Inc.' } }),
    );
    const result = await ioc004.run(makeContext(tempDir));
    expect(result.passed).toBe(true);
  });

  it('flags a skill from an ATR-sourced confirmed-malware publisher', async () => {
    const skillDir = join(tempDir, 'auto-updater-161ks');
    await mkdir(skillDir, { recursive: true });
    await writeFile(
      join(skillDir, 'package.json'),
      JSON.stringify({ name: 'auto-updater-161ks', author: 'hightower6eu' }),
    );
    const result = await ioc004.run(makeContext(tempDir));
    expect(result.passed).toBe(false);
    expect(result.evidence![0].detail).toContain('hightower6eu');
  });
});

describe('IOC-005: Typosquatting', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'vaso-ioc005-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('passes when no skills directory', async () => {
    const result = await ioc005.run(makeContext(undefined));
    expect(result.passed).toBe(true);
  });

  it('flags a skill name within Levenshtein distance 2 of a trusted name', async () => {
    // "flesystem" is distance 1 from "filesystem".
    await mkdir(join(tempDir, 'flesystem'), { recursive: true });
    const result = await ioc005.run(makeContext(tempDir));
    expect(result.passed).toBe(false);
    expect(result.evidence![0].detail).toContain('filesystem');
  });

  it('passes for skill names that are not close to any trusted name', async () => {
    await mkdir(join(tempDir, 'unique-experimental-skill'), { recursive: true });
    const result = await ioc005.run(makeContext(tempDir));
    expect(result.passed).toBe(true);
  });
});

describe('IOC-006: Skill Name Patterns', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'vaso-ioc006-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('passes when no skills directory', async () => {
    const result = await ioc006.run(makeContext(undefined));
    expect(result.passed).toBe(true);
  });

  it('flags skill names matching malicious patterns (keylog)', async () => {
    await mkdir(join(tempDir, 'awesome-keylogger'), { recursive: true });
    const result = await ioc006.run(makeContext(tempDir));
    expect(result.passed).toBe(false);
    expect(result.evidence![0].detail).toContain('keylog');
  });

  it('passes for skill names that do not match any malicious pattern', async () => {
    await mkdir(join(tempDir, 'data-export-tool'), { recursive: true });
    const result = await ioc006.run(makeContext(tempDir));
    expect(result.passed).toBe(true);
  });
});
