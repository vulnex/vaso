import { describe, it, expect } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { compileRule } from './compiler.js';
import type { DeclarativeRule } from './schema.js';
import type { CheckResult } from '../core/types.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { getReporter, reportFormats } from '../reporting/index.js';
import { maskCredentialsInLine, maskCredentialsInText, toReportJson } from '../reporting/serialize.js';

/**
 * A literal in the value of a credential-named position — an assignment
 * target, keyword argument, dict / object / YAML key, subscript, shell
 * variable — in every code shape a skill file may hold, with the literal a
 * fallback, a ternary's branch, a call's default argument, a shell default or
 * on a continuation line. `§` is replaced by a planted value: no report
 * format, nor a baseline, may quote it.
 */
const SHAPES: Array<[string, string]> = [
  // Python
  ['py', 'password = os.getenv("DB_PASSWORD") or "§"'],
  ['py', "api_key = load_key() or '§'"],
  ['py', 'client_secret = os.environ["CS"] if os.environ.get("CS") else "§"'],
  ['py', 'conn = connect(host, password=getpw() or "§", user="u")'],
  ['py', 'conn = connect(host, password=getpw() or "§")'],
  ['py', 'self.password = getpw() or "§"'],
  ['py', 'config["password"] = os.getenv("X") or "§"'],
  ['py', "config['api_key'] = '§'"],
  ['py', 'os.environ["API_KEY"] = os.environ.get("X") or "§"'],
  ['py', 'password = (os.getenv("X")\n    or "§")'],
  ['py', 'token = os.getenv("X") or \\\n    "§"'],
  ['py', 'pwd = os.getenv("P") or "§"'],
  ['py', 'password = f"{os.getenv(\'X\') or \'§\'}"'],
  ['py', 'password = os.getenv("X") or os.getenv("Y", "§")'],
  ['py', 'secret_key = settings.get("secret_key", "§")'],
  ['py', 'api_key: str = os.getenv("X") or "§"'],
  ['py', 'password = os.getenv("X") or "§"  # fallback'],
  ['py', 'db = {"password": os.getenv("X") or "§"}'],
  ['py', 'db = {"host": "h", "password": os.getenv("X") or "§", "port": 5432}'],
  ['py', 'db = dict(user="u", password=os.environ.get("PW", "§"))'],
  ['py', 'password=getpw()or"§"'],
  ['py', 'def connect(password=os.getenv("X") or "§"): pass'],
  ['py', 'TOKEN = os.getenv("T") or "pre" + "§"'],
  ['py', 'client = Client(\n    api_key=os.getenv("K") or\n        "§",\n)'],
  // JS / TS
  ['js', 'const apiKey = getKey() || `§`;'],
  ['js', 'const cfg = { password: process.env.PW || "§" };'],
  ['js', 'const token = process.env.T ? process.env.T : "§";'],
  ['js', 'let secret = cfg.secret ?? "§";'],
  ['js', 'const apiKey2 = getKey() ||\n  "§";'],
  ['js', 'this.password = env.PW || "§";'],
  ['js', 'opts["apiKey"] = env.K || "§";'],
  ['js', 'connect({ user: "u", password: env.PW || "§" });'],
  ['js', 'password ||= "§";'],
  ['js', 'password ??= "§";'],
  ['js', 'const { password = "§" } = opts;'],
  ['js', 'function f(password = getPw() || "§") {}'],
  ['js', 'const apiKey3 = env.K || "pre" + "§";'],
  ['js', 'const apiKey4 = env.K || String("§");'],
  ['js', 'const headers = { Authorization: `Bearer ${tok}`, apiKey: env.K || `§` };'],
  ['ts', 'const apiKey: string = process.env.K ?? "§";'],
  ['ts', 'export const config = { auth: { token: process.env.T || \'§\' } };'],
  ['js', 'const cfg = {\n  token: process.env.T ||\n    "§",\n};'],
  // shell
  ['sh', 'PASSWORD=${DB_PW:-§}'],
  ['sh', 'export API_KEY="${KEY:-§}"'],
  ['sh', 'TOKEN="${TOKEN:=§}"'],
  ['sh', 'export SECRET=${SECRET-§}'],
  ['sh', 'DB_PASSWORD="${DB_PASSWORD:-§}" ./run'],
  // YAML
  ['yaml', 'password: ${DB_PASSWORD:-§}'],
  ['yaml', 'api_key: "${API_KEY:-§}"'],
  // PHP, Ruby, Go, Rust, Kotlin, Java
  ['php', "$password = getenv('X') ?: '§';"],
  ['php', "$config['password'] = getenv('X') ?: '§';"],
  ['php', "$db = ['password' => getenv('X') ?: '§'];"],
  ['rb', 'api_key = ENV["X"] || "S"'],
  ['rb', 'client = Client.new(token: ENV["T"] || "S")'],
  ['go', 'password := cmp.Or(os.Getenv("P"), "S")'],
  ['rs', 'let password = env::var("X").unwrap_or("S".to_string());'],
  ['kt', 'val apiKey = System.getenv("K") ?: "S"'],
  ['java', 'String password = System.getenv().getOrDefault("PW", "S");'],
];

/** Deterministic pseudo-random values (mulberry32). */
function rng(seed: number): () => number {
  let a = seed;
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@%^*_-.';

function planted(next: () => number, i: number): string {
  let s = '';
  const len = 8 + Math.floor(next() * 10);
  for (let k = 0; k < len; k++) s += ALPHABET[Math.floor(next() * ALPHABET.length)];
  // a recognisable core that no masking form (`abcd…(N chars)`) keeps
  return `Pz${i}q${s.replace(/[^A-Za-z0-9]/g, '') || 'x'}Lk`;
}

const rule = (id: string, regex: string, message: string): DeclarativeRule =>
  ({ id, name: id, category: 'config', severity: 'warning', description: 'd', pattern: { regex, target: 'skills', message } }) as DeclarativeRule;

describe('literal values under a credential name never reach a report', () => {
  it('per line', () => {
    const next = rng(7);
    for (const [i, [, shape]] of SHAPES.entries()) {
      for (let round = 0; round < 4; round++) {
        const secret = planted(next, i);
        const text = shape.replaceAll('§', secret);
        for (const line of text.split('\n')) {
          if (!/(?:password|api|token|secret|key|pwd)/i.test(line)) continue;
          expect(maskCredentialsInLine(line), line).not.toContain(secret);
          expect(maskCredentialsInText(line), line).not.toContain(secret);
        }
      }
    }
  });

  it('in skill-file rule evidence, every report format and baselines', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vaso-cred-fuzz-'));
    try {
      const next = rng(42);
      const secrets: string[] = [];
      const files: string[] = [];
      for (const [i, [ext, shape]] of SHAPES.entries()) {
        const lines: string[] = [];
        for (let round = 0; round < 3; round++) {
          const secret = planted(next, i);
          secrets.push(secret);
          lines.push(shape.replaceAll('§', secret));
        }
        const file = join(dir, `s${i}.${ext}`);
        await writeFile(file, `${lines.join('\n')}\n`);
        files.push(file);
      }
      const ctx = {
        installation: { agent: 'claude-code' as const, installDir: dir, configFiles: [] },
        configs: [], platform: 'darwin' as const, fs: new LocalFSProvider(), skillFiles: files,
      };
      const results: CheckResult[] = [];
      for (const r of [
        rule('ORG-F1', 'api_?key|apiKey|API_KEY|token|TOKEN|passw|PASSW|pwd|secret|SECRET', 'hit in {{snippet}}'),
        rule('ORG-F2', 'Pz\\d', 'hit {{match}} in {{snippet}}'),
        rule('ORG-F3', '(apiKey|password|token|secret|PASSWORD|TOKEN|SECRET)[^;]*', 'assignment {{match}}'),
        rule('ORG-F4', '.', '{{snippet}}'),
      ]) results.push(await compileRule(r).run(ctx));
      for (const r of results) expect(r.passed, r.id).toBe(false);
      const scan = {
        timestamp: 't', totalScore: 0, totalGrade: 'F', fleetAverage: 0,
        summary: { critical: 0, warning: results.length, info: 0, passed: 0, total: results.length },
        agents: [{ agent: 'claude-code', score: 0, grade: 'F', installation: { agent: 'claude-code', installDir: dir, configFiles: [] }, results }],
      };
      const outputs: Array<[string, string]> = reportFormats().map(f => [f, getReporter(f).render(scan as never)]);
      outputs.push(['baseline', toReportJson(scan)]);
      for (const [format, out] of outputs) {
        for (const secret of secrets) expect(out, `${format}: ${secret}`).not.toContain(secret);
      }
      // the code around the values stays readable
      const json = outputs.find(([f]) => f === 'json')![1];
      for (const kept of ['os.getenv', 'process.env', 'DB_PASSWORD', 'getKey()']) expect(json).toContain(kept);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
