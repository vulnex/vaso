import { describe, it, expect, beforeAll } from 'vitest';
import { spawn, execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { dirname, extname, basename, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';

/**
 * Privacy canary: every place the probe collects from, filled with fake
 * secrets in the shapes the probe promises to disguise (doc/user-guide.md,
 * "Secrets in collected config files"), plus credential environment
 * variables. No secret's hidden part (all but the first 8 / last 4
 * characters reports show) may appear in the snapshot. Skill trees ship
 * verbatim by design (IOC checks hash them) and are left out; so are paths
 * outside HOME and command output, which a fixture can't plant.
 *
 * A new adapter path, file format or credential shape that the probe ships
 * as-is fails here, instead of being found by a test round.
 */

const ROOT = resolve(import.meta.dirname, '../..');
const CLI = join(ROOT, 'dist/cli.js');

const goAvailable = (() => {
  try {
    execFileSync('go', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();

function run(cmd: string, args: string[], env: NodeJS.ProcessEnv, cwd: string): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((done, fail) => {
    const child = spawn(cmd, args, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
    child.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });
    child.on('error', fail);
    child.on('close', code => done({ code: code ?? 1, stdout, stderr }));
  });
}

const BASE62 = 'ABCDEFGHIJKLMNOPQRSTUVWYZabcdefghijklmnopqrstuvwyz0123456789'; // no x/X: never a placeholder run
function body(n: number, alphabet = BASE62): string {
  const bytes = randomBytes(n);
  return Array.from(bytes, b => alphabet[b % alphabet.length]).join('');
}

/** One canary per planted value, by label (file + shape) for the failure message. */
const canaries = new Map<string, string>();
function canary(label: string, make: () => string): string {
  const value = make();
  canaries.set(label, value);
  return value;
}

/** The part of a secret the probe must never ship (reports show the rest). */
function hidden(s: string): string {
  return s.length >= 24 ? s.slice(8, -4) : s.length >= 16 ? s.slice(4) : s;
}

// Known key formats (API_KEY_PATTERNS plus the probe's extra token shapes)
const FORMATS: Array<[string, () => string]> = [
  ['anthropic', () => `sk-ant-api03-${body(40)}`],
  ['openai', () => `sk-proj-${body(40)}`],
  ['openrouter', () => `sk-or-v1-${body(48, 'abcdef0123456789')}`],
  ['github', () => `ghp_${body(36)}`],
  ['aws', () => `AKIA${body(16, 'ABCDEFGHIJKLMNOPQRSTUVWYZ234567')}`],
  ['slack', () => `xoxb-${body(11, '0123456789')}-${body(12, '0123456789')}-${body(24)}`],
  ['telegram', () => `${body(10, '123456789')}:AA${body(33)}`],
  ['nvidia', () => `nvapi-${body(40)}`],
  ['gitlab', () => `glpat-${body(24)}`],
  ['google', () => `AIza${body(35)}`],
  ['devin', () => `devin-${body(80)}`],
];

/** A random credential under a credential-named key: no known prefix. */
const generic = () => `${body(12)}!${body(14)}#${body(10)}`;

function textFile(label: string): string {
  return FORMATS.map(([name, make]) => `${name}: ${canary(`${label} ${name}`, make)}`).join('\n') + '\n';
}

function envFile(label: string): string {
  return [
    `ANTHROPIC_API_KEY=${canary(`${label} env anthropic`, FORMATS[0][1])}`,
    `export TELEGRAM_BOT_TOKEN="${canary(`${label} env telegram`, FORMATS[6][1])}" # bot`,
    `API_SERVER_KEY=${canary(`${label} env generic`, generic)}`,
    `#OPENAI_API_KEY=${canary(`${label} env commented`, FORMATS[1][1])}`,
    `DATABASE_URL=postgres://app:${canary(`${label} env url password`, () => body(28))}@db.internal:5432/app`,
  ].join('\n') + '\n';
}

function jsonFile(label: string): string {
  const c = (shape: string, make: () => string) => canary(`${label} json ${shape}`, make);
  return JSON.stringify({
    apiKey: c('apiKey', generic),
    NVIDIA_API_KEY: c('nvidia', FORMATS[7][1]),
    providers: [{ name: 'x', api_key: c('nested api_key', generic) }],
    mcpServers: {
      s: {
        command: 'npx',
        args: ['-y', 'server', '--api-key', c('argv flag', generic), `--token=${c('argv inline', generic)}`],
        env: { GITHUB_TOKEN: c('env token', FORMATS[3][1]), SLACK_BOT_TOKEN: c('env slack', FORMATS[5][1]) },
        headers: { Authorization: `Bearer ${c('bearer', generic)}` },
        url: `https://user:${c('url password', () => body(30))}@mcp.example.com/sse?api_key=${c('url param', () => body(30))}`,
      },
    },
    notes: `token ${c('token in prose', FORMATS[0][1])}`,
  }, null, 2) + '\n';
}

function yamlFile(label: string): string {
  return [
    'providers:',
    `  - api_key: "${canary(`${label} yaml api_key`, generic)}"  # key`,
    `    password: ${canary(`${label} yaml password`, generic)}`,
    `    token: ${canary(`${label} yaml token`, FORMATS[4][1])}`,
  ].join('\n') + '\n';
}

function tomlFile(label: string): string {
  return [
    '[provider]',
    `api_key = "${canary(`${label} toml api_key`, generic)}"`,
    `env = { OPENAI_API_KEY = "${canary(`${label} toml inline`, FORMATS[1][1])}" }`,
  ].join('\n') + '\n';
}

function pemFile(label: string): string {
  return `-----BEGIN RSA PRIVATE KEY-----\n${canary(`${label} pem body`, () => body(64))}\n-----END RSA PRIVATE KEY-----\n`;
}

function contentFor(path: string): string {
  const name = basename(path).toLowerCase();
  const ext = extname(name);
  if (name.startsWith('.env') || ext === '.env') return envFile(path);
  if (ext === '.json' || ext === '.jsonc' || ext === '.json5') return jsonFile(path);
  if (ext === '.yaml' || ext === '.yml') return yamlFile(path);
  if (ext === '.toml' || ext === '.ini' || ext === '.cfg' || ext === '.conf') return tomlFile(path);
  if (ext === '.pem' || ext === '.key') return pemFile(path);
  return textFile(path);
}

/** A concrete path under HOME for a manifest entry, or undefined when it can't be planted. */
function concrete(entry: string): string | undefined {
  if (!entry.startsWith('~/') || entry.includes('$') || /\/skills\//.test(entry) || entry.includes('node_modules')) return undefined;
  let p = entry.slice(2)
    .replace(/\{([^,}]*)(?:,[^}]*)?\}/g, '$1') // {a,b} → a
    .replace(/\*\*\//g, '')
    .replace(/\*/g, 'canary')
    .replace(/\?/g, 'c')
    .replace(/\[[^\]]*\]/g, 'c');
  if (p.endsWith('/') || p === '') return undefined;
  // A glob ending in a bare wildcard names no format; give it one
  if (basename(p) === 'canary') p += '.json';
  return p;
}

describe.skipIf(!goAvailable)('probe privacy canary', () => {
  let home: string;
  let snapshot: string;
  let planted = 0;

  beforeAll(async () => {
    const work = await mkdtemp(join(tmpdir(), 'vaso-canary-'));
    home = join(work, 'home');
    await mkdir(home);
    const probe = join(work, 'vaso-probe');
    execFileSync('go', ['build', '-o', probe, '.'], { cwd: join(ROOT, 'probe'), stdio: 'ignore' });

    const baseEnv = { HOME: home, PATH: '/usr/bin:/bin', NO_COLOR: '1', VASO_SKIP_IOC_UPDATE: '1', TMPDIR: tmpdir() };
    const m = await run(process.execPath, [CLI, 'probe', 'manifest'], baseEnv, home);
    expect(m.code).toBe(0);
    const manifest = JSON.parse(m.stdout) as { filePaths: string[]; globPatterns: string[]; metadataGlobPatterns?: string[]; envPrefixes: string[] };

    const paths = new Set<string>();
    for (const e of [...manifest.filePaths, ...manifest.globPatterns, ...(manifest.metadataGlobPatterns ?? [])]) {
      const p = concrete(e);
      if (p) paths.add(p);
    }
    for (const rel of [...paths].sort()) {
      const full = join(home, rel);
      try {
        await mkdir(dirname(full), { recursive: true });
        await writeFile(full, contentFor(rel), { flag: 'wx' });
        planted++;
      } catch {
        // a path that another entry made a directory (or a file) — skip it
      }
    }
    await writeFile(join(work, 'manifest.json'), m.stdout);

    // Credential variables under every collected prefix (the probe redacts them)
    const env: NodeJS.ProcessEnv = { ...baseEnv };
    for (const prefix of manifest.envPrefixes) {
      const base = prefix.endsWith('_') ? prefix : `${prefix}_`;
      env[`${base}API_KEY`] = canary(`env ${base}API_KEY`, generic);
      env[`${base}ORG`] = canary(`env ${base}ORG (token by shape)`, FORMATS[1][1]);
      env[`${base}PROXY_URL`] = `https://u:${canary(`env ${base}PROXY_URL password`, () => body(28))}@proxy.example.com:3128`;
    }
    const r = await run(probe, ['--manifest', join(work, 'manifest.json')], env, home);
    expect(r.code, r.stderr).toBe(0);
    snapshot = r.stdout;
  }, 300_000);

  it('plants canaries across the manifest', () => {
    expect(planted).toBeGreaterThan(300);
    expect(canaries.size).toBeGreaterThan(2000);
  });

  it('ships no canary', () => {
    const leaks = [...canaries].filter(([, value]) => snapshot.includes(hidden(value))).map(([label]) => label);
    expect(leaks, `${leaks.length} canaries shipped:\n${leaks.slice(0, 40).join('\n')}`).toEqual([]);
  });
});
