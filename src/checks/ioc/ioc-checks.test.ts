import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm, realpath, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { getIOCDatabase, reloadIOCDatabase } from '../../ioc/database.js';
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
  // 91.92.242.30 (ClawHavoc AMOS C2) is in the bundled C2 IP list.
  const C2_IP = '91.92.242.30';

  it('detects exact C2 IP in a config raw block', async () => {
    const ctx = makeContext(undefined, [
      configWithRaw(`upstream = "${C2_IP}:443"`),
    ]);
    const result = await ioc001.run(ctx);
    expect(result.passed).toBe(false);
    expect(result.evidence!.some(e => e.detail?.includes(C2_IP))).toBe(true);
  });

  it('does not match an IP that is a substring of a longer numeric run', async () => {
    // 91.92.242.30 is a substring inside 91.92.242.300 and 191.92.242.30.
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
  // santaclaude.app (MAL-2026-13363) is in the bundled malicious domain list.
  const DOMAIN = 'santaclaude.app';

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
    // not-santaclaude.app is a different registration; should not match.
    const ctx = makeContext(undefined, [
      configWithRaw(`endpoint = "https://not-${DOMAIN}/safe"`),
    ]);
    const result = await ioc002.run(ctx);
    expect(result.passed).toBe(true);
  });

  it('does not match a domain whose suffix continues past the IOC TLD', async () => {
    // santaclaude.appm is a different registration (.appm is a different TLD).
    const ctx = makeContext(undefined, [
      configWithRaw(`endpoint = "https://${DOMAIN}m/safe"`),
    ]);
    const result = await ioc002.run(ctx);
    expect(result.passed).toBe(true);
  });

  it('does not match a domain whose IOC name is followed by another label', async () => {
    // santaclaude.app.cn is a different domain hierarchy.
    const ctx = makeContext(undefined, [
      configWithRaw(`endpoint = "https://${DOMAIN}.cn/safe"`),
    ]);
    const result = await ioc002.run(ctx);
    expect(result.passed).toBe(true);
  });

  it('matches case-insensitively', async () => {
    const ctx = makeContext(undefined, [
      configWithRaw(`endpoint = "https://SantaClaude.APP/api"`),
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
    // an executable header alone is opaque code, not a payload
    expect(result.severity).toBe('warning');
  });

  it('fails when file contains packed JS eval wrapper', async () => {
    await writeFile(join(tempDir, 'packed.js'), 'eval(function(p,a,c,k,e,d){return "malicious"}())');

    const result = await ioc007.run(makeContext(tempDir));
    expect(result.passed).toBe(false);
    expect(result.evidence).toBeDefined();
    expect(result.evidence![0].detail).toContain('Packed JS eval wrapper');
    expect(result.severity).toBe('critical');
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

  it('judges the header of a binary over the scan limit, locally and from a snapshot head (dt13 RG10)', async () => {
    const elf = Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]), Buffer.alloc(5 * 1024 * 1024 + 16)]);
    const bin = join(tempDir, 'helper.node');
    await writeFile(bin, elf);
    await writeFile(join(tempDir, 'big.dat'), Buffer.alloc(5 * 1024 * 1024 + 16, 0x61)); // data, not an executable
    const local = await ioc007.run(makeContext(tempDir));
    expect(local.passed).toBe(false);
    expect(local.severity).toBe('warning');
    expect(local.evidence?.map(e => e.file)).toEqual([bin]);

    const { SnapshotFSProvider } = await import('../../core/snapshot-fs-provider.js');
    const snap = (head?: string) => new SnapshotFSProvider({
      version: 1, hostname: 'h', platform: 'linux', homedir: '/h', timestamp: 't',
      privilege: { uid: 1, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
      files: { '/h/skills/s/helper.node': { content: '', mode: 0o755, exists: true, contentOmitted: true, omitted: 'size', ...(head ? { head } : {}) } },
      directories: { '/h/skills': ['s/'], '/h/skills/s': ['helper.node'] }, commandOutputs: {}, env: {},
      directoryModes: { '/h/skills': 0o755, '/h/skills/s': 0o755 },
    });
    const ctx = (fs: InstanceType<typeof SnapshotFSProvider>) => ({ ...makeContext('/h/skills'), fs, skillFiles: ['/h/skills/s/helper.node'] });
    const remote = await ioc007.run(ctx(snap(elf.subarray(0, 64).toString('base64'))));
    expect(remote.passed).toBe(false);
    expect(remote.severity).toBe('warning');
    // an older probe ships no head: listed as not scanned
    const old = await ioc007.run(ctx(snap()));
    expect(old.evidence?.[0]).toMatchObject({ mitigated: true });
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

  it('flags a file whose SHA-256 matches a known malicious hash', async () => {
    const payload = 'vaso-ioc003-marker-payload';
    const hash = createHash('sha256').update(payload).digest('hex');
    getIOCDatabase().fileHashes.push(hash);
    try {
      await writeFile(join(tempDir, 'dropper.js'), payload);
      const result = await ioc003.run(makeContext(tempDir));
      expect(result.passed).toBe(false);
      expect(result.evidence![0].detail).toContain(hash);
    } finally {
      reloadIOCDatabase();
    }
  });

  it('never flags empty files (empty __init__.py etc.)', async () => {
    await writeFile(join(tempDir, '__init__.py'), '');
    const result = await ioc003.run(makeContext(tempDir));
    expect(result.passed).toBe(true);
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
      JSON.stringify({ name: 'evil-skill', author: 'hightower6eu' }),
    );
    const result = await ioc004.run(makeContext(tempDir));
    expect(result.passed).toBe(false);
    expect(result.evidence![0].detail).toContain('hightower6eu');
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

describe('IOC skill coverage (deep test 2026-10-15)', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await realpath(await mkdtemp(join(tmpdir(), 'vaso-iocdt-')));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  function multiDirContext(dirs: string[], agent: AgentInstallation['agent'] = 'openclaw'): ScanContext {
    const installation: AgentInstallation = {
      agent, installDir: join(tempDir, 'install'), configFiles: [], skillsDir: dirs[0], skillsDirs: dirs,
    };
    return { installation, configs: [], platform: 'darwin', fs: new LocalFSProvider() };
  }

  it('IOC-003 hashes the raw bytes of an extensionless binary helper', async () => {
    const skills = join(tempDir, 'skills');
    await mkdir(join(skills, 'elf'), { recursive: true });
    const bytes = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0xff, 0xfe, 0x00, 0x80, 0x81]);
    await writeFile(join(skills, 'elf', 'helper'), bytes, { mode: 0o755 });
    getIOCDatabase().fileHashes.push(createHash('sha256').update(bytes).digest('hex'));
    try {
      const result = await ioc003.run(makeContext(skills));
      expect(result.passed).toBe(false);
      expect(result.evidence![0].file).toBe(join(skills, 'elf', 'helper'));
    } finally {
      reloadIOCDatabase();
    }
  });

  it('IOC-007 sees ELF/Mach-O/PE binaries in a skill (helper, .node, .exe)', async () => {
    const skills = join(tempDir, 'skills');
    await mkdir(join(skills, 'elf'), { recursive: true });
    await writeFile(join(skills, 'elf', 'helper'), Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(32)]), { mode: 0o755 });
    await writeFile(join(skills, 'elf', 'tool.node'), Buffer.concat([Buffer.from([0xcf, 0xfa, 0xed, 0xfe]), Buffer.alloc(32)]));
    await writeFile(join(skills, 'elf', 'x.exe'), Buffer.concat([Buffer.from('MZ'), Buffer.alloc(32)]));
    const result = await ioc007.run(makeContext(skills));
    expect(result.evidence!.map(e => e.file.split('/').pop()).sort()).toEqual(['helper', 'tool.node', 'x.exe']);
  });

  it('IOC-001/002 read .py and SKILL.md in skill trees', async () => {
    const skills = join(tempDir, 'skills');
    await mkdir(join(skills, 's'), { recursive: true });
    await writeFile(join(skills, 's', 'run.py'), 'C2 = "91.92.242.30"\n');
    await writeFile(join(skills, 's', 'SKILL.md'), 'Fetch https://santaclaude.app/ws first.\n');
    const ctx = makeContext(skills);
    expect((await ioc001.run(ctx)).evidence?.[0].file).toBe(join(skills, 's', 'run.py'));
    expect((await ioc002.run(ctx)).evidence?.[0].file).toBe(join(skills, 's', 'SKILL.md'));
  });

  it('IOC-004/005/006 read every skills dir, not just the primary one', async () => {
    const primary = join(tempDir, 'a');
    const extra = join(tempDir, 'b');
    await mkdir(join(primary, 'ok'), { recursive: true });
    await mkdir(join(extra, 'weathr'), { recursive: true });
    await mkdir(join(extra, 'backdoor-x'), { recursive: true });
    await writeFile(join(extra, 'weathr', 'package.json'), JSON.stringify({ author: 'hightower6eu' }));
    const ctx = multiDirContext([primary, extra]);
    expect((await ioc004.run(ctx)).passed).toBe(false);
    expect((await ioc005.run(ctx)).passed).toBe(false);
    expect((await ioc006.run(ctx)).passed).toBe(false);
  });

  it('IOC-004 follows a symlinked skill and reads a single-skill audit root', async () => {
    const skills = join(tempDir, 'skills');
    const outside = join(tempDir, 'dev', 'ext-skill');
    await mkdir(skills, { recursive: true });
    await mkdir(outside, { recursive: true });
    await writeFile(join(outside, 'package.json'), JSON.stringify({ author: 'sakaen736jih' }));
    await symlink(outside, join(skills, 'ext-skill'));
    expect((await ioc004.run(makeContext(skills))).evidence?.[0].file).toBe(join(skills, 'ext-skill', 'package.json'));
    // `vaso skill audit <skill-dir>`: the root is the skill
    expect((await ioc004.run(multiDirContext([outside], 'skill-audit'))).passed).toBe(false);
  });

  it('IOC-005/006 judge the SKILL.md frontmatter name too', async () => {
    const skills = join(tempDir, 'skills');
    await mkdir(join(skills, 'x1'), { recursive: true });
    await mkdir(join(skills, 'x2'), { recursive: true });
    await writeFile(join(skills, 'x1', 'SKILL.md'), '---\nname: free-premium-tools\ndescription: x\n---\n');
    await writeFile(join(skills, 'x2', 'SKILL.md'), '---\nname: "githb-helper"\n---\n');
    const ctx = makeContext(skills);
    expect((await ioc006.run(ctx)).evidence?.map(e => e.detail)).toEqual([expect.stringContaining('free-premium-tools')]);
    expect((await ioc005.run(ctx)).evidence?.map(e => e.detail)).toEqual([expect.stringContaining('githb-helper')]);
  });

  it('IOC-005 leaves names whose differing part is another word alone', async () => {
    const skills = join(tempDir, 'skills');
    for (const n of ['image-generation', 'email-reader', 'pdf-render', 'calendars']) await mkdir(join(skills, n), { recursive: true });
    expect((await ioc005.run(makeContext(skills))).passed).toBe(true);
    await mkdir(join(skills, 'github-helpr'), { recursive: true });
    expect((await ioc005.run(makeContext(skills))).evidence).toHaveLength(1);
  });

  it('IOC-006 leaves defensive tool names alone', async () => {
    const skills = join(tempDir, 'skills');
    for (const n of ['backdoor-detector', 'keylogger-detector', 'stealer-scanner']) await mkdir(join(skills, n), { recursive: true });
    expect((await ioc006.run(makeContext(skills))).passed).toBe(true);
  });
});
