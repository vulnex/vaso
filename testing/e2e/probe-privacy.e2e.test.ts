import { describe, it, expect, beforeAll } from 'vitest';
import { spawn, execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmod, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import { dirname, extname, basename, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';

/**
 * Privacy canary: every place the probe collects from, filled with fake
 * secrets in the shapes the probe promises to disguise (doc/user-guide.md,
 * "Secrets in collected config files"), plus credential environment
 * variables. No secret's hidden part (all but the first 8 / last 4
 * characters reports show) may appear in the snapshot, nor may a stand-in
 * keep more of a hex key than chance. Files are also written with CRLF line
 * endings, a BOM, a Latin-1 byte or as UTF-16 (base64 in the snapshot,
 * searched decoded). Skill trees ship
 * verbatim by design (IOC checks hash them) and are left out; so are paths
 * outside HOME and command output, which a fixture can't plant.
 *
 * A new adapter path, file format or credential shape that the probe ships
 * as-is fails here, instead of being found by a test round.
 */

const ROOT = resolve(import.meta.dirname, '../..');
// VASO_E2E_CLI: a bundle built elsewhere (fix rounds share dist/)
const CLI = process.env.VASO_E2E_CLI ?? join(ROOT, 'dist/cli.js');

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

/**
 * Values too short to search for alone (a 5-character token), and email
 * addresses (whose first character stays): never shipped in the context
 * they were planted in — the whole `"NAME": "value"`, `NAME=value`, address.
 */
const contextCanaries = new Map<string, string>();
function contextCanary(label: string, value: string, context: (v: string) => string): string {
  contextCanaries.set(label, context(value));
  return value;
}
const LOWER = 'abcdefghijklmnopqrstuvwyz';
/** A lowercase word: what a password or token often is, no marker in it. */
const lowerWord = () => body(11, LOWER);

/** The part of a secret the probe must never ship (reports show the rest). */
function hidden(s: string): string {
  return s.length >= 24 ? s.slice(8, -4) : s.length >= 16 ? s.slice(4) : s;
}

/**
 * Secrets written wholly in escapes (\u0041 in JSON and TOML, \x41 in YAML):
 * the escapes of their hidden characters, of which no run of eight may ship.
 */
const escapedCanaries = new Map<string, string[]>();
const jsonEscape = (ch: string) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`;
const yamlEscape = (ch: string) => `\\x${ch.charCodeAt(0).toString(16).padStart(2, '0')}`;
function escapedCanary(label: string, make: () => string, escape: (ch: string) => string): string {
  const value = make();
  escapedCanaries.set(label, [...hidden(value)].map(escape));
  return [...value].map(escape).join('');
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
  ['airtable', () => `pat${body(14)}.${body(64, 'abcdef0123456789')}`],  ['vault', () => `hvs.${body(90)}`],
];

/** A diceware-style passphrase: lowercase words, no digit or capital. */
const passphrase = () => Array.from({ length: 4 }, () => body(7, 'abcdefghijklmnopqrstuvwyz')).join('-');

/**
 * A random credential under a credential-named key: no known prefix. A
 * digit in it always: in free text the CLI takes a random run with no digit
 * and entropy under 4.5 for prose, and so does the probe.
 */
const generic = () => `${body(11)}${body(1, '0123456789')}!${body(14)}#${body(10)}`;
/** A password of letters with a digit in it, nothing the shell would read. */
const alnum = () => `${body(7)}${body(1, '0123456789')}${body(6)}`;

/** A short random credential (12–15 characters with digits: the CLI flags it from 12). */
const short = () => `${body(5)}${body(3, '0123456789')}${body(5)}`;

/** Random order of distinct characters: high entropy whatever the draw. */
function distinct(alphabet: string, n: number): string[] {
  const a = [...alphabet];
  const r = randomBytes(a.length);
  for (let i = a.length - 1; i > 0; i--) {
    const j = r[i] % (i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a.slice(0, n);
}

/**
 * A base64 secret that starts with "/" (one in 64 does): no file path. Its
 * characters are distinct and a "+" splits it — a low-entropy draw, or one
 * that happens to split into words, reads as a path name on both sides
 * (isPathValue) and is kept like one.
 */
const slashed = () => {
  const s = distinct([...distinct(BASE62.replace(/\d/g, ''), 26), ...distinct('0123456789', 4)].join(''), 30).join('');
  return `/${s.slice(0, 15)}+${s.slice(15)}`;
};

/** Hex keys, whose stand-ins are also checked for reversibility. */
const HEX = '0123456789abcdef';
const hexCanaries = new Set<string>();
const hex = () => {
  const v = body(40, HEX);
  hexCanaries.add(v);
  return v;
};

function textFile(label: string): string {
  return FORMATS.map(([name, make]) => `${name}: ${canary(`${label} ${name}`, make)}`).join('\n') + '\n';
}

function envFile(label: string): string {
  return [
    `ANTHROPIC_API_KEY=${canary(`${label} env anthropic`, FORMATS[0][1])}`,
    `export TELEGRAM_BOT_TOKEN="${canary(`${label} env telegram`, FORMATS[6][1])}" # bot`,
    `API_SERVER_KEY=${canary(`${label} env generic`, generic)}`,
    `DB_PASSWORD=${canary(`${label} env passphrase`, passphrase)}`,
    `#OPENAI_API_KEY=${canary(`${label} env commented`, FORMATS[1][1])}`,
    `DATABASE_URL=postgres://app:${canary(`${label} env url password`, () => body(28))}@db.internal:5432/app`,
    `REDIS_URL=redis://:${canary(`${label} env url password, no user`, () => body(28))}@cache:6379`,
    `DATADOG_API_KEY=${canary(`${label} env hex`, hex)}`,
    `DB_PWD=${canary(`${label} env pwd`, generic)}`,
    `WEBHOOK_SECRET=${canary(`${label} env short`, short)}`,
    `EXTRA_ARGS="--verbose --api-key ${canary(`${label} env argv`, generic)}"`,
    `NUMERIC_PASSWORD=${canary(`${label} env numeric password`, () => body(9, '123456789'))}`,
    `LOWER_PASSWORD=${canary(`${label} env lowercase password`, () => body(12, 'abcdefghijklmnopqrstuvwyz'))}`,
    `QUOTED_ARGS='--no-auth --password "${canary(`${label} env quoted password`, () => `${body(6)} ${body(7)}2`)}"'`,
    // low-entropy values under names that hold a key, and a short one
    `PRIVATE_KEY=${canary(`${label} env lowercase PRIVATE_KEY`, lowerWord)}`,
    `ACCESS_KEY=${canary(`${label} env lowercase ACCESS_KEY`, lowerWord)}`,
    `GITHUB_PAT=${contextCanary(`${label} env short GITHUB_PAT`, body(5, LOWER), v => `GITHUB_PAT=${v}`)}`,
    `DB_URL=mysql://root:${canary(`${label} env lowercase url password`, lowerWord)}@localhost/db`,
    // quoted values closed on a line below (python-dotenv reads them whole)
    `SLACK_BOT_TOKEN='${canary(`${label} env single-quoted line 1`, short)}`,
    `${canary(`${label} env single-quoted line 2`, short)}'`,
    `MULTI_API_KEY="${canary(`${label} env double-quoted line 1`, short)}`,
    `  ${canary(`${label} env double-quoted line 2`, short)}"`,
    // backtick-quoted, over two lines (Node's dotenv reads it whole)
    `OPENROUTER_API_KEY=\`${canary(`${label} env backtick line 1`, short)}`,
    `${canary(`${label} env backtick line 2`, short)}\``,
    `GATEWAY_TOKEN=\`${canary(`${label} env backtick one line`, generic)}\``,
  ].join('\n') + '\n';
}

function jsonFile(label: string): string {
  const c = (shape: string, make: () => string) => canary(`${label} json ${shape}`, make);
  return JSON.stringify({
    apiKey: c('apiKey', generic),
    FN_ANTHROPIC_PASSWORD: c('passphrase', passphrase),
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
      // capability URLs: the path is the credential (findUrlSecrets)
      zapier: { url: `https://mcp.zapier.com/api/mcp/s/${c('zapier secret path', () => `${body(46)}==`)}/mcp` },
      zapierKey: { url: `https://actions.zapier.com/mcp/${c('zapier sk-ak key', () => `sk-ak-${body(32)}`)}/sse` },
      discord: { url: `https://discord.com/api/webhooks/123456789012345678/${c('discord webhook token', () => body(68))}` },
      capability: { url: `https://mcp.example.com/u/${c('random path token', () => body(48))}/sse` },
      fragment: { url: `https://mcp.example.com/mcp#access_token=${c('fragment token', () => body(32))}` },
      telegram: { url: `https://api.telegram.org/bot${c('telegram bot token in path', FORMATS[6][1])}/sendMessage` },
      signed: { url: `https://x.example.com/api?sig=${c('sig param', () => body(32))}&X-Amz-Signature=${c('amz signature', () => body(64, 'abcdef0123456789'))}` },
      session: { url: `https://x.example.com/p;jsessionid=${c('jsessionid', () => body(32))}` },
      catchHook: { url: `https://hooks.zapier.com/hooks/catch/123456/${c('zapier catch key', () => body(16, 'abcdefghijklmnopqrstuvwyz0123456789'))}/` },
      // plain values in credential positions: a lowercase word after a
      // credential flag or as a URL's password; low-entropy and short values
      // under names that hold a key, token or session
      plain: {
        command: 'npx',
        args: ['-y', 'db-mcp', '--password', c('lowercase --password', lowerWord), '--db', `postgres://admin:${c('lowercase url password', lowerWord)}@db.internal/x`,
          `--api-key=${c('lowercase --api-key=', lowerWord)}`, '--token', c('lowercase --token', lowerWord), '--auth', c('lowercase --auth', lowerWord),
          '--secret', c('lowercase --secret', lowerWord), `https://u:${c('lowercase url password in argv', lowerWord)}@x.example/y`],
        env: {
          DATABASE_URL: `mysql://root:${c('lowercase env url password', lowerWord)}@localhost/db`,
          PRIVATE_KEY: c('lowercase PRIVATE_KEY', lowerWord),
          AUTH: c('lowercase AUTH', lowerWord),
          ACCESS_KEY: c('lowercase ACCESS_KEY', lowerWord),
          SESSION: c('lowercase SESSION', lowerWord),
          PAT: c('lowercase PAT', lowerWord),
          TELEGRAM_BOT_TOKEN: contextCanary(`${label} json short TELEGRAM_BOT_TOKEN`, body(5, LOWER), v => `"TELEGRAM_BOT_TOKEN": "${v}"`),
          API_KEY: contextCanary(`${label} json short API_KEY`, body(4, BASE62), v => `"API_KEY": "${v}"`),
        },
      },
    },
    // an account's email address: personal data, its first character and domain stay
    oauthAccount: { emailAddress: contextCanary(`${label} json email address`, `${body(12, LOWER)}@example.com`, v => v) },
    notes: `token ${c('token in prose', FORMATS[0][1])}`,
    // key=\"value\" inside a JSON string (custom instructions)
    instructions: `password="${c('escaped-quoted pair', generic)}" and api_key: "${c('escaped-quoted colon pair', generic)}"`,
    userName: 'Jos\u00e9',
    // lists, maps and argv the one-value rules missed
    api_keys: [c('array item 1', generic), c('array item 2', hex)],
    secrets: { github: c('secrets map child', generic), name: 'x' },
    DB_PASSWORD: c('slash-leading base64', slashed),
    NPM_CONFIG__AUTH: `//registry.npmjs.org/:_authToken=${c('npm authToken after a path', generic)}`,
    SERVICE_TOKEN: `\${DB_PASSWORD:-${c('env fallback', generic)}}`,
    API_SECRET: `$${c('dollar-led password', () => `Zx8${body(20)}`)}`,
    tools: {
      a: { args: ['-y', 'acme-mcp', '--verbose', '--token', c('argv after boolean flag', generic)] },
      b: { args: ['supergateway', `--header=Authorization: Bearer ${c('header flag with =', generic)}`, `redis://:${c('url password, no user', () => body(28))}@cache:6379`] },
      c: { command: 'sh', args: ['-c', `mysql -uroot -p${c('mysql -p', generic)} app && sshpass -p ${c('sshpass -p', generic)} ssh host`] },
      d: { url: `https://${c('token as url user', () => body(32))}@o1.ingest.sentry.io/1`, args: ['--pwd', c('--pwd', generic)] },
      e: { args: ['acme', '--no-auth', '--api-key', c('flag after a secret-named switch', generic)] },
      f: { command: 'mysql', args: ['-u', 'root', `-p${c('-p<password> element', () => `${body(10)}7${body(9)}`)}`] },
      g: { url: `https://${c('token:@ url user', () => body(32))}:@x.example/sse` },
      h: { url: `https://x.example/sse#${c('fragment token', () => distinct(BASE62, 30).join(''))}` },
      // the shared argv rules (probe/testdata/argv-verdicts.json)
      j: { args: ['acme', '--api-key', `-${c('dash-led value', () => distinct(BASE62, 24).join(''))}`] },
      // glued: mysql reads a separate value after -p as the database name
      k: { command: 'mysql', args: ['-u', 'root', `-p${c('mysql -p date-like', () => `20${body(2, '0123456789')}.${body(2, '0123456789')}.${body(2, '0123456789')}${body(6, '0123456789')}`)}`] },
      l: { command: 'sshpass', args: ['-p', c('sshpass lowercase', () => body(14, 'abcdefghijklmnopqrstuvwyz')), 'ssh', 'host'] },
      m: { command: 'redis-cli', args: ['-h', 'cache', '-p', '6379', '-a', c('redis-cli -a', () => body(16, 'abcdefghijklmnopqrstuvwyz'))] },
      n: { args: ['-k', c('-k base64 with / and +', () => { const d = distinct(BASE62, 26).join(''); return `${d.slice(0, 13)}/${d.slice(13)}+`; })] },
      // -k takes a key only when what follows is random (the report masker's rule)
      i: { args: ['-k', c('-k random key', () => distinct(BASE62, 30).join(''))] },
      // curl user:password as separate elements (rule 5); --pw/--pass take a password
      o: { command: 'curl', args: ['-u', `carol:${c('curl -u separate', lowerWord)}`, '--user', `dave:${c('curl --user separate', lowerWord)}`, `--proxy-user=p:${c('curl --proxy-user=', lowerWord)}`, 'https://x.example'] },
      p: { command: 'acme', args: ['--pw', c('lowercase --pw', lowerWord), '--pass', c('lowercase --pass', lowerWord)] },
    },
    // hook commands: passwords quoted the shell's way, nested in remote and
    // shell commands (in the JSON text the double quotes are escaped)
    hooks: {
      PostToolUse: [{
        matcher: 'Bash',
        hooks: [
          `mysql -p"${c('hook mysql -p"pw"', alnum)}" app`,
          `mysql -p'${c("hook mysql -p'pw'", alnum)}' app`,
          `sshpass -p "${c('hook sshpass -p "pw"', alnum)}" ssh x`,
          `curl -u "adm:${c('hook curl -u "u:pw"', alnum)}" https://x.example`,
          `mysql --password="${c('hook mysql --password="pw"', lowerWord)}" app`,
          `MYSQL_PWD="${c('hook MYSQL_PWD="pw"', lowerWord)}" mysql app`,
          `PGPASSWORD=${c('hook PGPASSWORD=pw', lowerWord)} psql -h db app`,
          `ssh h 'mysql -p"${c('hook ssh \'mysql -p"pw"\'', alnum)}" app'`,
          `ssh h "sshpass -p \\"${c('hook ssh "sshpass -p \\"pw\\""', alnum)}\\" ssh x"`,
          `ssh h $'mysql -p${c("hook ssh $'mysql -ppw'", alnum)} app'`,
          `ssh host "bash -c 'mysql -p${c('hook two levels', alnum)} app'"`,
        ].map(command => ({ type: 'command', command })),
      }],
    },
    api_key: c('all-lowercase api key', () => body(32, 'abcdefghijklmnopqrstuvwyz0123456789')),
    // a pasted curl command: JSON inside the string, its quotes escaped twice
    curl: `Run: curl -d "{\\"api_key\\":\\"${c('embedded JSON in a JSON string', generic)}\\"}" https://api.x.com`,
    // the value under a credential-named key, a level down
    credentials: { primary: { value: c('credentials.primary.value', short), name: 'main' } },
    // compact nesting (replaced below): one container's { is the next key's prefix
    compact: '@COMPACT@',
    auth: { type: 'bearer', value: c('auth.value', short) },
    ESCAPED_API_KEY: '@ESCAPED@',
    // random strings deeper under a secrets container
    creds: [{ k: c('creds array of objects', generic) }],
    vault: { credentials: [[c('credentials array of arrays', generic)]], tokens: { x: { y: c('tokens deep map', generic) } } },
    // a credential after more text than one container walk reads (one file)
    ...(label === '.cursor/mcp.json' ? {
      store: { credentials: { note: 'lorem ipsum dolor '.repeat(4000), primary: c('credential after a 70 KiB note', generic) } },
      store2: { credentials: { ...Object.fromEntries(Array.from({ length: 9000 }, (_, i) => [`k${i}`, 1])), primary: c('credential after 9000 keys', generic) } },
    } : {}),
  }, null, 2).replace('"@ESCAPED@"', `"${escapedCanary(`${label} json all-escaped key`, generic, jsonEscape)}"`)
    .replace('"@COMPACT@"', `{"creds": {"value": "${canary(`${label} json compact creds.value`, lowerWord)}"}}`) + '\n';
}

/** JSON5 as OpenClaw writes it: unquoted keys, single quotes, comments, trailing commas. */
function json5File(label: string): string {
  const c = (shape: string, make: () => string) => canary(`${label} json5 ${shape}`, make);
  return [
    '// gateway',
    '{',
    '  gateway: {',
    `    auth: { mode: 'token', token: '${c('token', generic)}', password: "${c('password', generic)}" },`,
    '  },',
    `  'channels': { discord: { token: '${c('quoted key', generic)}' }, telegram: { botToken: "${c('telegram', FORMATS[6][1])}" } },`,
    '  mcp: { servers: {',
    `    a: { command: 'npx', args: ['-y', 'x-mcp@1.0.0', '--api-key', '${c('argv flag', generic)}'], env: { MY_SERVICE_TOKEN: '${c('env', generic)}' } },`,
    '  } },',
    '}',
  ].join('\n') + '\n';
}

function yamlFile(label: string): string {
  return [
    'providers:',
    `  - api_key: "${canary(`${label} yaml api_key`, generic)}"  # key`,
    `    password: ${canary(`${label} yaml password`, generic)}`,
    `    token: ${canary(`${label} yaml token`, FORMATS[4][1])}`,
    `vision: {provider: custom, base_url: "https://vision.example.com/v1", api_key: "${canary(`${label} yaml flow`, generic)}"}`,
    `svc: {command: npx, args: [-y, "svc-mcp@1.2.3", --token, ${canary(`${label} yaml flow argv`, generic)}], env: {SVC_API_TOKEN: ${canary(`${label} yaml flow plain`, generic)}}}`,
    `anchored_token: &tok ${canary(`${label} yaml anchor`, generic)}`,
    `tagged_secret: !!str ${canary(`${label} yaml tag`, generic)}`,
    `list_tokens: [${canary(`${label} yaml flow sequence`, generic)}]`,
    'model_list:',
    '  m:',
    '    api_keys:',
    `      - ${canary(`${label} yaml block list`, generic)}`,
    `      - "${canary(`${label} yaml block list quoted`, hex)}"`,
    'anchored_keys: &keys',
    `  - &k1 ${canary(`${label} yaml anchored list item`, generic)}`,
    `  - !!str ${canary(`${label} yaml tagged list item`, generic)}`,
    'headers:',
    '  ? X-Other',
    // a header no rule names: disguised when random
    `  : ${canary(`${label} yaml explicit header key`, () => distinct(BASE62, 32).join(''))}`,
    'deep:',
    '  secrets:',
    '    nested:',
    `      deeper: ${canary(`${label} yaml secrets grandchild`, generic)}`,
    'aux:',
    '  api_key:',
    `    ${canary(`${label} yaml next-line value`, generic)}`,
    'secrets:',
    `  github: ${canary(`${label} yaml secrets map child`, generic)}`,
    // flow sequences with the command beside them (block or inline mapping)
    'flow_servers:',
    '  c1:',
    '    command: sshpass',
    `    args: ["-p", "${canary(`${label} yaml flow argv sshpass`, () => `${body(4)}!${body(5)}`)}", "ssh", "host"]`,
    `  c4: {command: sshpass, args: [-p, "${canary(`${label} yaml inline mapping argv`, () => `${body(4)}!${body(5)}`)}", ssh, h]}`,
    '  c5:',
    '    command: mysql',
    // glued: mysql reads a separate value after -p as the database name
    `    args: ["-u", "root", "-p${canary(`${label} yaml flow argv mysql`, () => `${body(3)}!${body(5)}`)}"]`,
    'mcp:',
    '  args:',
    '    - --verbose',
    '    - --api-key',
    `    - ${canary(`${label} yaml argv block`, generic)}`,
    'curl:',
    '  command: curl',
    '  args:',
    '    - -u',
    `    - carol:${canary(`${label} yaml curl -u block`, lowerWord)}`,
    '    - --pw',
    `    - ${canary(`${label} yaml --pw block`, lowerWord)}`,
    `escaped_password: "${escapedCanary(`${label} yaml all-escaped password`, generic, yamlEscape)}"`,
    // credentials written over two lines: folded, literal, plain
    'multi:',
    '  api_key: >-',
    `    ${canary(`${label} yaml folded line 1`, short)}`,
    `    ${canary(`${label} yaml folded line 2`, short)}`,
    '  secret: |',
    `    ${canary(`${label} yaml literal line 1`, short)}`,
    `    ${canary(`${label} yaml literal line 2`, short)}`,
    '  token:',
    `    ${canary(`${label} yaml plain next-line 1`, short)}`,
    `    ${canary(`${label} yaml plain next-line 2`, short)}`,
    `  password: ${canary(`${label} yaml plain same-line 1`, short)}`,
    `    ${canary(`${label} yaml plain same-line 2`, short)}`,
    'credentials:',
    '  primary:',
    `    value: ${canary(`${label} yaml credentials.primary.value`, short)}`,
    // quoted scalars over lines, a plain one ended by a comment
    'quoted:',
    `  api_key: "${canary(`${label} yaml double-quoted line 1`, short)}`,
    `    ${canary(`${label} yaml double-quoted line 2`, short)}"`,
    `  auth_token: '${canary(`${label} yaml single-quoted line 1`, short)}`,
    '',
    `    ${canary(`${label} yaml single-quoted line 2`, short)}'`,
    `  secret_token: ${canary(`${label} yaml plain commented line 1`, short)}`,
    `    ${canary(`${label} yaml plain commented line 2`, short)} # rotated`,
    // an anchored value read under a credential name through an alias
    'aliases:',
    `  BASE: &base ${canary(`${label} yaml aliased anchor`, () => body(32))}`,
    '  OPENAI_API_KEY: *base',
    `  COMMON: &pw ${canary(`${label} yaml aliased lowercase`, lowerWord)}`,
    '  DB_PASSWORD: *pw',
  ].join('\n') + '\n';
}

function tomlFile(label: string): string {
  return [
    '[provider]',
    `api_key = "${canary(`${label} toml api_key`, generic)}"`,
    `bearer_token = """${canary(`${label} toml multi-line string`, generic)}"""`,
    // multi-line strings over lines: basic, a line break escaped, literal
    `ml_token = """${canary(`${label} toml basic line 1`, short)}`,
    `${canary(`${label} toml basic line 2`, short)}"""`,
    `bs_token = """${canary(`${label} toml escaped break line 1`, short)}\\`,
    `   ${canary(`${label} toml escaped break line 2`, short)}"""`,
    "lit_secret = '''",
    `${canary(`${label} toml literal line 1`, short)}`,
    `  ${canary(`${label} toml literal line 2`, short)}'''`,
    `env = { OPENAI_API_KEY = "${canary(`${label} toml inline`, FORMATS[1][1])}" }`,
    `api_keys = ["${canary(`${label} toml array`, generic)}", "${canary(`${label} toml array hex`, hex)}"]`,
    `tokens = { primary = "${canary(`${label} toml inline table child`, generic)}" }`,
    '[http_request.secrets]',
    `github = "${canary(`${label} toml secrets table child`, generic)}"`,
    '[secrets.nested]',
    `github = "${canary(`${label} toml secrets subtable child`, generic)}"`,
    '[providers.x]',
    `api_key."main" = "${canary(`${label} toml dotted quoted key`, generic)}"`,
    '[mcp_servers.curl]',
    'command = "curl"',
    `args = ["-u", "carol:${canary(`${label} toml curl -u`, lowerWord)}", "--pass", "${canary(`${label} toml --pass`, lowerWord)}"]`,
    '[mcp_servers.curl.env]',
    `API_KEY = "${escapedCanary(`${label} toml all-escaped key`, generic, jsonEscape)}"`,
    `credentials = { primary = { value = "${canary(`${label} toml credentials.primary.value`, short)}", name = "main" } }`,
    `nested = { CREDS = { value = "${canary(`${label} toml creds.value lowercase`, lowerWord)}" } }`,
  ].join('\n') + '\n';
}

/** Instruction and memory files: keyed secrets in prose, plus every key format. */
function markdownFile(label: string): string {
  const c = (shape: string, make: () => string) => canary(`${label} md ${shape}`, make);
  return [
    '# Project notes',
    `DB_PASSWORD=${c('dotenv line', generic)}`,
    `- api_key: ${c('list item', generic)}`,
    `Use \`"client_secret": "${c('quoted pair', generic)}"\` for the staging app.`,
    `curl -H "Authorization: Bearer ${c('bearer', generic)}" -u bob:${c('curl -u', generic)} https://api.example.com`,
    `Run \`OPENAI_API_KEY=${c('env prefix', generic)} node x.js --api-key ${c('flag', generic)}\`.`,
    // values holding the punctuation that ends a word: disguised whole
    `signing_secret: "${c('quoted &', () => `${generic()}&${generic()}`)}"`,
    `signing_secret: "${c('quoted ;', () => `${generic()};${generic()}`)}"`,
    `signing_secret: "${c('quoted space', () => `${generic()} ${generic()}`)}"`,
    `* token = "${c("quoted '", () => `${generic()}'${generic()}`)}"`,
    `SECRET_KEY=${c('unquoted |', () => `${generic()}|${generic()}`)}`,
    `password: ${c('unquoted ,', () => `${generic()},${generic()}`)}`,
    `| API_KEY | ${c('table cell', () => body(40))} |`,
    `**API key**: ${c('bold label', () => body(40))}`,
    `Zapier: (https://mcp.zapier.com/api/mcp/s/${c('zapier url in prose', () => body(48))}/mcp).`,
    // a value the rest of the line would make no credential (CLI: first word)
    `API_KEY=${c('value then url', generic)} for https://x.example.com`,
    `curl -H 'Authorization: Bearer ${c('single-quoted bearer then url', generic)}' https://api.example.com`,
    `token: ${c('value then placeholder word', generic)} (see the example in the wiki)`,
    `password: ${c('value then comma', generic)}, replace monthly`,
    `API_KEY=${c('value then ellipsis', generic)} and so on...`,
    `DB_PWD=${c('pwd', generic)}`,
    `Token del servidor: ${c('multi-word name', generic)}`,
    `**password**: ${c('short bold value', short)}`,
    `| DB_PASSWORD | ${c('short table cell', short)} |`,
    `token: @${c('@-led value', generic)}`,
    `HEX_SECRET=${c('hex', hex)}`,
    // half of a disguised token pasted elsewhere in the file
    ...(() => {
      const t = distinct(BASE62, 60).join('') + distinct(BASE62, 40).join('');
      return [`TOKEN="${t}"`, `The first half: \`${c('copied half of a token', () => t.slice(0, 60))}\``];
    })(),
  ].join('\n') + '\n' + textFile(label);
}

function pemFile(label: string): string {
  return `-----BEGIN RSA PRIVATE KEY-----\n${canary(`${label} pem body`, () => body(64))}\n-----END RSA PRIVATE KEY-----\n`;
}

/**
 * The bytes a file is written as: a sixth of the files each with CRLF line
 * endings, a BOM and CRLF, a Latin-1 byte (Windows editors), as UTF-16 with
 * a BOM, or as big-endian UTF-16 without one.
 */
function encodeFor(index: number, content: string): Buffer {
  switch (index % 6) {
    case 5: return Buffer.from(`# Настройки сервера\n${content}`, 'utf16le').swap16();
    case 1: return Buffer.from(content.replace(/\n/g, '\r\n'));
    case 2: return Buffer.from(`\uFEFF${content.replace(/\n/g, '\r\n')}`);
    case 3: return Buffer.from(content.includes('\u00e9') ? content : `${content}# Configuraci\u00f3n\n`, 'latin1');
    case 4: return Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(content, 'utf16le')]);
    default: return Buffer.from(content);
  }
}

function contentFor(path: string): string {
  const name = basename(path).toLowerCase();
  const ext = extname(name);
  if (name.startsWith('.env') || ext === '.env') return envFile(path);
  if (ext === '.json5' || name === 'openclaw.json') return json5File(path);
  if (ext === '.json' || ext === '.jsonc') return jsonFile(path);
  if (ext === '.yaml' || ext === '.yml') return yamlFile(path);
  if (ext === '.toml' || ext === '.ini' || ext === '.cfg' || ext === '.conf') return tomlFile(path);
  if (ext === '.pem' || ext === '.key') return pemFile(path);
  if (ext === '.md' || ext === '.mdc' || ext === '.txt') return markdownFile(path);
  return textFile(path);
}

/** A concrete path under HOME for a manifest entry, or undefined when it can't be planted. */
function concrete(entry: string): string | undefined {
  // skill trees (skills/, skills-cursor/, custom_skills/ …) ship as they are
  if (!entry.startsWith('~/') || entry.includes('$') || /\/(?:[^/]*[-_.])?skills?(?:[-_.][^/]*)?\//i.test(entry) || entry.includes('node_modules')) return undefined;
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

/**
 * Paths agents' configs set (configRoots): the configs (still full of
 * canaries) point workspaces and extra skill dirs at trees whose files carry
 * canaries — walked, and disguised like any config — at the home itself, a
 * credential store and the root (refused), and name MCP commands and a
 * tirith binary whose content is canaries (stat'd, never read).
 */
const CONFIG_TREE_FILES: Record<string, string> = {
  'canary-ws/skills/s1/notes.md': 'md',
  'canary-ws/skills/s1/settings.json': 'json',
  'canary-ws/skills/s1/.env': 'env',
  'canary-ws/skills/s1/tool.py': 'text',
  'canary-ws/plugins/p/config.yaml': 'yaml',
  'canary-oc/skills/o/SKILL.md': 'md',
  'canary-extra/pack/x.toml': 'toml',
  'canary-zc/skills/z/SKILL.md': 'md',
  '.zeroclaw/bundle/b/settings.json': 'json',
};
/** Never collected: beside a walked tree, or under a refused base. */
const CONFIG_ROOT_UNCOLLECTED = ['canary-ws/private.env', '.canary-home.env', '.ssh/id_canary', '.aws/canary-credentials'];
/** Outside the scanned home (another user's): never collected, whatever links or configs point there. */
const OUTSIDE_HOME = ['notes/secret.md', 'skills/s/tool.py'];
/** Links inside a walked config tree that lead out of the home or into a store. */
const ESCAPE_LINKS: Record<string, string> = {
  'canary-extra/pack/etc': '/private/etc',
  'canary-extra/pack/etc2': '/etc',
  'canary-extra/pack/gh': '../../.config/gh',
  'canary-extra/pack/ssh': '../../.ssh',
};
/**
 * Credential-named files inside a walked config tree: metadata only, an
 * executable bit notwithstanding (a key or token with +x is no program).
 */
const CONFIG_TREE_CREDENTIALS: Record<string, { mode: number; content: (label: string) => string }> = {
  'canary-extra/pack/.vault-token': { mode: 0o600, content: l => canary(l, () => `hvs.${body(90)}`) },
  'canary-extra/pack/.legacy/.vault-token': { mode: 0o600, content: l => canary(l, () => `s.${body(24)}`) },
  'canary-extra/pack/.psql_history': { mode: 0o600, content: l => `ALTER USER admin PASSWORD '${canary(l, short)}';\n` },
  'canary-extra/pack/.mysql_history': { mode: 0o600, content: l => `SET PASSWORD = '${canary(l, short)}';\n` },
  'canary-extra/pack/.bash_history': { mode: 0o600, content: l => `mysql -p${canary(l, short)}\n` },
  'canary-extra/pack/.local/share/keyrings/login.keyring': { mode: 0o600, content: l => canary(l, () => body(40)) },
  'canary-extra/pack/.local/share/keyrings/default': { mode: 0o600, content: l => canary(l, () => body(40)) },
  'canary-extra/pack/Vivaldi/Default/Cookies': { mode: 0o600, content: l => `SQLite format 3 ${canary(l, () => body(40))}` },
  'canary-extra/pack/Vivaldi/Default/Login Data': { mode: 0o600, content: l => canary(l, () => body(40)) },
  'canary-extra/pack/Vivaldi/Default/Web Data': { mode: 0o600, content: l => canary(l, () => body(40)) },
  'canary-extra/pack/id_ed25519': { mode: 0o755, content: l => `b3BlbnNzaC1rZXktdjE${canary(l, () => body(64))}\n` },
  'canary-extra/pack/secrets.json': { mode: 0o755, content: l => `{"x": "${canary(l, () => body(40))}"}\n` },
};
const CONFIG_COMMANDS = ['canary-bin/hermes-server', 'canary-bin/tirith', 'canary-bin/cd-server', 'canary-bin/at-server'];

async function plantConfigRoots(home: string): Promise<void> {
  const put = async (rel: string, content: string) => {
    await mkdir(dirname(join(home, rel)), { recursive: true });
    await writeFile(join(home, rel), content);
  };
  const json = (label: string, extra: Record<string, unknown>) =>
    JSON.stringify({ ...JSON.parse(jsonFile(label)), ...extra }, null, 2) + '\n';
  const at = (rel: string) => join(home, rel);
  await put('.nanobot/config.json', json('nanobot root config', { agents: { defaults: { workspace: '~/canary-ws' } } }));
  await put('.openclaw/openclaw.json', json('openclaw root config', {
    agents: { defaults: { workspace: '~/canary-oc' } },
    skills: { load: { extraDirs: ['~', '~/.ssh', '/', '~/canary-extra', '/private/etc', '/etc', otherHome(home), '~/.config/gh', '~/.config', '~/to-other'] } },
  }));
  await put('.zeroclaw/config.toml', tomlFile('zeroclaw root config') + [
    '[agents.main.workspace]', 'path = "~/canary-zc"',
    '[skill_bundles.b]', 'directory = "bundle"',
    '[skills]', 'open_skills_enabled = true', 'open_skills_dir = "~/.aws"',
  ].join('\n') + '\n');
  await put('.hermes/config.yaml', [
    'mcp_servers:', '  srv:', `    command: ${at(CONFIG_COMMANDS[0])}`,
    'security:', `  tirith_path: ~/${CONFIG_COMMANDS[1]}`,
  ].join('\n') + '\n' + yamlFile('hermes root config'));
  // Low-entropy values under key and token names are credentials too
  const lower = () => body(20, 'abcdefghijklmnopqrstuvwyz');
  await put('Library/Application Support/Claude/claude_desktop_config.json',
    json('claude desktop root config', { mcpServers: {
      srv: { command: at(CONFIG_COMMANDS[2]) },
      low: {
        command: 'npx',
        env: { API_KEY: canary('low-entropy env API_KEY', lower), GITHUB_TOKEN: canary('low-entropy env GITHUB_TOKEN', lower) },
        headers: { Authorization: `Bearer ${canary('low-entropy Authorization bearer', lower)}`, 'X-Api-Key': canary('low-entropy X-Api-Key', lower) },
      },
    } }));
  await put('.atomic-agent/config.json',
    json('atomic root config', { mcp: { servers: [{ name: 'srv', transport: { kind: 'stdio', command: at(CONFIG_COMMANDS[3]) } }] } }));
  const make: Record<string, (label: string) => string> = { md: markdownFile, json: jsonFile, env: envFile, text: textFile, yaml: yamlFile, toml: tomlFile };
  for (const [rel, kind] of Object.entries(CONFIG_TREE_FILES)) await put(rel, make[kind](rel));
  for (const rel of CONFIG_ROOT_UNCOLLECTED) await put(rel, envFile(rel));
  for (const [rel, { mode, content }] of Object.entries(CONFIG_TREE_CREDENTIALS)) {
    await put(rel, content(`config tree credential ${rel}`));
    await chmod(join(home, rel), mode);
  }
  for (const rel of CONFIG_COMMANDS) await put(rel, `#!/bin/sh\n${textFile(rel)}`);
  for (const rel of OUTSIDE_HOME) {
    await mkdir(dirname(join(otherHome(home), rel)), { recursive: true });
    await writeFile(join(otherHome(home), rel), envFile(`other user ${rel}`));
  }
  await symlink(otherHome(home), join(home, 'to-other'));
  await symlink(otherHome(home), join(home, 'canary-extra/pack/other'));
  for (const [rel, target] of Object.entries(ESCAPE_LINKS)) await symlink(target, join(home, rel));
  // Linked per-agent workspaces under a manifest glob (~/.picoclaw/workspace-*/skills/**):
  // one inside the home (walked, disguised), one into another user's home (refused)
  await put('canary-pc/skills/p/settings.json', jsonFile('canary-pc/skills/p/settings.json'));
  await mkdir(join(home, '.picoclaw'), { recursive: true });
  await symlink(join(home, 'canary-pc'), join(home, '.picoclaw/workspace-in'));
  await symlink(otherHome(home), join(home, '.picoclaw/workspace-out'));
}

/**
 * Copilot store folders linked to places that aren't the agent's — a store
 * folder itself (to a dir out of the home, to ~/.aws, to the home) and folders
 * linked inside a store (out of the home, to ~/.ssh, to the home, to
 * ~/.copilot) — with files whose NAMES are canaries behind each: the probe
 * records the links only, so no such name may ship. A folder linked inside
 * the home is followed as before (STORE_LINK_FOLLOWED).
 */
const STORE_LINK_NAME = 'CANARYNAME';
const STORE_LINK_FOLLOWED = 'canary-sess/events.jsonl';

async function plantStoreLinks(home: string, work: string): Promise<{ links: string[]; followed: string }> {
  const put = async (path: string) => {
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, '{}\n');
  };
  const outA = join(work, 'store-out-a');
  const outB = join(work, 'store-out-b');
  await put(join(outA, `${STORE_LINK_NAME}-out-a.json`));
  await put(join(outA, 'sub', `${STORE_LINK_NAME}-out-a-sub.jsonl`));
  await put(join(outB, `${STORE_LINK_NAME}-out-b.json`));
  await put(join(outB, 'session', `${STORE_LINK_NAME}-out-b-sub.jsonl`));
  await put(join(home, '.aws', `${STORE_LINK_NAME}-aws.json`));
  await put(join(home, '.aws', 'sso', `${STORE_LINK_NAME}-aws-sub.json`));
  await put(join(home, '.ssh', `${STORE_LINK_NAME}-ssh`));
  await put(join(home, `${STORE_LINK_NAME}-home.json`));
  await put(join(home, `${STORE_LINK_NAME}-dir`, `${STORE_LINK_NAME}-home-sub.json`));
  await put(join(home, STORE_LINK_FOLLOWED));
  const cop = join(home, '.copilot');
  const links: Record<string, string> = {
    'mcp-secrets': outA,
    'mcp-oauth-config': join(home, '.aws'),
    'command-history-state': home,
    'session-state/linked-out': outB,
    'session-state/linked-ssh': join(home, '.ssh'),
    'session-state/linked-home': home,
    'session-state/linked-agent': cop,
  };
  for (const [rel, target] of Object.entries(links)) {
    await rm(join(cop, rel), { recursive: true, force: true });
    await mkdir(dirname(join(cop, rel)), { recursive: true });
    await symlink(target, join(cop, rel));
  }
  await symlink(join(home, 'canary-sess'), join(cop, 'session-state/linked-ok'));
  return { links: Object.keys(links).map(rel => join(cop, rel)), followed: join(cop, 'session-state/linked-ok/events.jsonl') };
}

/**
 * Skills trees that reach agents' own files through links: a skill file
 * linked to Claude Code's token file, a skill folder linked to ~/.codex, and
 * skills roots linked to ~/.claude and to ~/.config (gh's oauth_token beside
 * the planted configs). Skill trees ship verbatim, so whatever they reach is
 * judged by where it really is: credential stores not at all, metadata-only
 * stores as metadata, configs disguised.
 */
const SKILL_LINK_SINKS = [
  '.claude/skills/canary-cred/c.json',
  '.claude/skills/canary-codex/auth.json',
  '.agents/skills/.credentials.json',
  '.cursor/skills/gh/hosts.yml',
];

async function plantSkillLinks(home: string): Promise<void> {
  const put = async (rel: string, content: string) => {
    await mkdir(dirname(join(home, rel)), { recursive: true });
    await writeFile(join(home, rel), content);
  };
  await put('.config/gh/hosts.yml', yamlFile('.config/gh/hosts.yml') + `github.com:\n  oauth_token: ${canary('gh oauth_token behind a skills link', () => `gho_${body(36)}`)}\n`);
  await put('.claude/skills/canary-cred/SKILL.md', '---\nname: canary-cred\n---\n');
  await symlink(join(home, '.claude/.credentials.json'), join(home, '.claude/skills/canary-cred/c.json'));
  await symlink(join(home, '.codex'), join(home, '.claude/skills/canary-codex'));
  for (const [root, target] of [['.agents/skills', '.claude'], ['.cursor/skills', '.config']]) {
    await rm(join(home, root), { recursive: true, force: true });
    await mkdir(dirname(join(home, root)), { recursive: true });
    await symlink(join(home, target), join(home, root));
  }
}

/** A directory beside the scanned home, standing in for another user's. */
function otherHome(home: string): string {
  return join(dirname(home), 'other-user');
}

describe.skipIf(!goAvailable)('probe privacy canary', () => {
  let home: string;
  let snapshot: string;
  let planted = 0;
  let geminiIndex = '';
  let haystack = '';
  /** The collected files' text, decoded (as the snapshot's JSON strings and base64 hold it). */
  let contentText = '';
  let storeLinks: { links: string[]; followed: string } = { links: [], followed: '' };

  beforeAll(async () => {
    const work = await mkdtemp(join(tmpdir(), 'vaso-canary-'));
    home = join(work, 'home');
    await mkdir(home);
    const probe = join(work, 'vaso-probe');
    // VASO_E2E_PROBE_SRC: another probe source tree (an older release, to show the canary catches it)
    execFileSync('go', ['build', '-o', probe, '.'], { cwd: process.env.VASO_E2E_PROBE_SRC ?? join(ROOT, 'probe'), stdio: 'ignore' });

    const baseEnv = { HOME: home, PATH: '/usr/bin:/bin', NO_COLOR: '1', VASO_SKIP_IOC_UPDATE: '1', TMPDIR: tmpdir() };
    const m = await run(process.execPath, [CLI, 'probe', 'manifest'], baseEnv, home);
    expect(m.code).toBe(0);
    const manifest = JSON.parse(m.stdout) as { filePaths: string[]; globPatterns: string[]; metadataGlobPatterns?: string[]; envPrefixes: string[]; envPresence?: string[] };

    const paths = new Set<string>();
    for (const e of [...manifest.filePaths, ...manifest.globPatterns, ...(manifest.metadataGlobPatterns ?? [])]) {
      const p = concrete(e);
      if (p) paths.add(p);
    }
    for (const [i, rel] of [...paths].sort().entries()) {
      const full = join(home, rel);
      try {
        await mkdir(dirname(full), { recursive: true });
        await writeFile(full, encodeFor(i, contentFor(rel)), { flag: 'wx' });
        planted++;
      } catch {
        // a path that another entry made a directory (or a file) — skip it
      }
    }
    // Gemini's tmp dir: only the project memory index ships (disguised);
    // chats, logs and other memory files never do (decision 2, 2026-11-09)
    for (const rel of ['chats/session-2026-11-09T10-00-abc.json', 'chats/session-1.jsonl', 'logs.json', 'shell_history', 'memory/notes.md', 'checkpoint-x.json']) {
      const full = join(home, '.gemini/tmp/proj-1', rel);
      await mkdir(dirname(full), { recursive: true });
      await writeFile(full, contentFor(`.gemini/tmp/proj-1/${rel}`));
    }
    geminiIndex = join(home, '.gemini/tmp/proj-1/memory/MEMORY.md');
    await writeFile(geminiIndex, contentFor('.gemini/tmp/proj-1/memory/MEMORY.md'));
    await plantConfigRoots(home);
    storeLinks = await plantStoreLinks(home, work);
    await plantSkillLinks(home);
    await writeFile(join(work, 'manifest.json'), m.stdout);

    // Credential variables under every collected prefix (the probe redacts them)
    const env: NodeJS.ProcessEnv = { ...baseEnv };
    for (const prefix of manifest.envPrefixes) {
      const base = prefix.endsWith('_') ? prefix : `${prefix}_`;
      env[`${base}API_KEY`] = canary(`env ${base}API_KEY`, generic);
      env[`${base}ORG`] = canary(`env ${base}ORG (token by shape)`, FORMATS[1][1]);
      env[`${base}PROXY_URL`] = `https://u:${canary(`env ${base}PROXY_URL password`, () => body(28))}@proxy.example.com:3128`;
      env[`${base}EXTRA_ARGS`] = `--model x --api-key ${canary(`env ${base}EXTRA_ARGS argv`, generic)}`;
      env[`${base}PW`] = canary(`env ${base}PW`, generic);
    }
    // Presence-only variables (FLY_MACHINE_ID…): set or not, never the value —
    // nor a longer name the old prefix rule matched
    expect(manifest.envPresence?.length).toBeGreaterThan(0);
    for (const name of manifest.envPresence ?? []) {
      env[name] = canary(`env ${name} (presence only)`, () => body(24));
      env[`${name}_X`] = canary(`env ${name}_X (presence-only prefix)`, generic);
    }
    const r = await run(probe, ['--manifest', join(work, 'manifest.json')], env, home);
    expect(r.code, r.stderr).toBe(0);
    snapshot = r.stdout;
    // base64 contents (not UTF-8) are searched decoded, as Latin-1 and UTF-16
    const files = (JSON.parse(snapshot) as { files: Record<string, { content?: string; encoding?: string }> }).files;
    haystack = [snapshot, ...Object.values(files)
      .filter(e => e.encoding === 'base64' && e.content)
      .flatMap(e => {
        const raw = Buffer.from(e.content!, 'base64');
        const even = raw.subarray(0, raw.length - (raw.length % 2));
        return [raw.toString('latin1'), raw.toString('utf16le'), raw.subarray(1).toString('utf16le'), Buffer.from(even).swap16().toString('utf16le')];
      })].join('\n');
    contentText = Object.values(files).flatMap(e => {
      if (!e.content) return [];
      if (e.encoding !== 'base64') return [e.content];
      const raw = Buffer.from(e.content, 'base64');
      const even = raw.subarray(0, raw.length - (raw.length % 2));
      return [raw.toString('latin1'), raw.toString('utf16le'), raw.subarray(1).toString('utf16le'), Buffer.from(even).swap16().toString('utf16le')];
    }).join('\n');
  }, 300_000);

  it('plants canaries across the manifest', () => {
    expect(planted).toBeGreaterThan(300);
    expect(canaries.size).toBeGreaterThan(2000);
  });

  it('ships the Gemini memory index with content, nothing else from its tmp dir', () => {
    const files = (JSON.parse(snapshot) as { files: Record<string, { exists: boolean; content: string; contentOmitted?: boolean }> }).files;
    expect(files[geminiIndex]?.exists).toBe(true);
    expect(files[geminiIndex]?.contentOmitted).toBeFalsy();
    expect(files[geminiIndex]?.content).toContain('# Project notes');
    const tmpContent = Object.entries(files)
      .filter(([p, e]) => p.includes('/.gemini/tmp/') && e.exists && !e.contentOmitted)
      .map(([p]) => p);
    expect(tmpContent.every(p => p.endsWith('/memory/MEMORY.md')), tmpContent.join('\n')).toBe(true);
  });

  it('walks config-set trees (disguised), refuses home, root and credential stores, and stats config-named commands', () => {
    const snap = JSON.parse(snapshot) as {
      files: Record<string, { exists: boolean; content?: string; contentOmitted?: boolean }>;
      configTrees?: Record<string, string>;
    };
    for (const rel of Object.keys(CONFIG_TREE_FILES)) {
      expect(snap.files[join(home, rel)]?.content, `${rel} collected`).toBeTruthy();
    }
    for (const rel of CONFIG_ROOT_UNCOLLECTED) expect(snap.files[join(home, rel)], `${rel} not collected`).toBeUndefined();
    for (const rel of Object.keys(CONFIG_TREE_CREDENTIALS)) {
      const e = snap.files[join(home, rel)];
      expect(e?.exists, `${rel} recorded`).toBe(true);
      expect(e?.content ?? '', `${rel} metadata only`).toBe('');
    }
    for (const rel of CONFIG_COMMANDS) {
      const e = snap.files[join(home, rel)];
      expect(e?.exists, `${rel} stat'd`).toBe(true);
      expect(e?.contentOmitted).toBe(true);
      expect(e?.content ?? '').toBe('');
    }
    expect(snap.configTrees).toMatchObject({
      [join(home, 'canary-ws/skills')]: 'collected',
      [join(home, 'canary-extra')]: 'collected',
      [home]: 'refused',
      [join(home, '.ssh')]: 'refused',
      [join(home, '.aws')]: 'refused',
      '/': 'refused',
      '/private/etc': 'refused',
      '/etc': 'refused',
      [otherHome(home)]: 'refused',
      [join(home, '.config/gh')]: 'refused',
      [join(home, 'to-other')]: 'refused',
      [join(home, '.picoclaw/workspace-in/skills')]: 'collected',
      [join(home, '.picoclaw/workspace-out/skills')]: 'refused',
    });
    expect(snap.files[join(home, '.picoclaw/workspace-in/skills/p/settings.json')]?.content).toBeTruthy();
    expect(Object.keys(snap.files).filter(p => p.startsWith(join(home, '.picoclaw/workspace-out') + '/'))).toEqual([]);
    // nothing from /etc or the other user's home ships content — through a
    // config or a link to it — and a walked tree's links out of the home or
    // into a store are recorded as links only, nothing behind them
    const real = (p: string) => { try { return realpathSync(p); } catch { return p; } };
    const forbidden = ['/etc/', '/private/etc/', real(otherHome(home)) + '/'];
    for (const [p, e] of Object.entries(snap.files)) {
      if (e.content) expect(forbidden.some(f => p.startsWith(f) || real(p).startsWith(f)), `content shipped for ${p}`).toBe(false);
    }
    for (const rel of [...Object.keys(ESCAPE_LINKS), 'canary-extra/pack/other']) {
      const leaked = Object.keys(snap.files).filter(p => p === join(home, rel) || p.startsWith(join(home, rel) + '/'));
      expect(leaked, rel).toEqual([]);
    }
  });

  it('records Copilot store links to foreign places as links only, nothing behind them', () => {
    const snap = JSON.parse(snapshot) as {
      files: Record<string, { exists: boolean; content?: string }>;
      symlinks?: Record<string, string>;
      directories: Record<string, string[]>;
    };
    expect(snapshot.includes(STORE_LINK_NAME), 'a name from behind a foreign store link shipped').toBe(false);
    for (const link of storeLinks.links) {
      expect(snap.symlinks?.[link], `${link} recorded`).toBeTruthy();
      expect(snap.directories[link], `${link} not listed`).toBeUndefined();
      expect(Object.keys(snap.files).filter(p => p.startsWith(link + '/')), link).toEqual([]);
    }
    expect(snap.files[storeLinks.followed]?.exists, 'a folder linked inside the home is followed').toBe(true);
    expect(snap.files[storeLinks.followed]?.content ?? '').toBe('');
  });

  it('ships no agent credential a skills tree reaches through a link', () => {
    const snap = JSON.parse(snapshot) as { files: Record<string, { exists: boolean; content?: string; omitted?: string }> };
    for (const rel of SKILL_LINK_SINKS) {
      const e = snap.files[join(home, rel)];
      expect(e?.exists, `${rel} recorded`).toBe(true);
      expect(e?.omitted, rel).toBe('sensitive');
      expect(e?.content ?? '', rel).toBe('');
    }
  });

  it('ships no canary', () => {
    const leaks = [...canaries].filter(([, value]) => haystack.includes(hidden(value))).map(([label]) => label);
    expect(leaks, `${leaks.length} canaries shipped:\n${leaks.slice(0, 40).join('\n')}`).toEqual([]);
  });

  it('ships no run of an escaped secret\'s escapes', () => {
    expect(escapedCanaries.size).toBeGreaterThan(200);
    const leaks = [...escapedCanaries].filter(([, esc]) => {
      for (let i = 0; i + 8 <= esc.length; i++) if (contentText.includes(esc.slice(i, i + 8).join(''))) return true;
      return false;
    }).map(([label]) => label);
    expect(leaks, `${leaks.length} escaped canaries shipped:\n${leaks.slice(0, 40).join('\n')}`).toEqual([]);
  });

  it('ships no short credential or email address in its context', () => {
    expect(contextCanaries.size).toBeGreaterThan(300);
    const leaks = [...contextCanaries].filter(([, context]) => contentText.includes(context)).map(([label, context]) => `${label}: ${context}`);
    expect(leaks, `${leaks.length} shipped:\n${leaks.slice(0, 40).join('\n')}`).toEqual([]);
  });

  it('gives no character away over many snapshots', async () => {
    // One small HOME collected again and again: a stand-in drawn without
    // its original character (or with its class kept in place) shows over
    // a few dozen snapshots which character each position held. Each draw
    // must include the original, so it turns up about as often as chance.
    const work = await mkdtemp(join(tmpdir(), 'vaso-canary-multi-'));
    const probe = join(work, 'vaso-probe');
    execFileSync('go', ['build', '-o', probe, '.'], { cwd: process.env.VASO_E2E_PROBE_SRC ?? join(ROOT, 'probe'), stdio: 'ignore' });
    const h = join(work, 'home');
    const pemBody = body(64, BASE62 + '+/');
    const hexKeys = Array.from({ length: 12 }, () => body(40, HEX));
    await mkdir(join(h, '.claude'), { recursive: true });
    await writeFile(join(h, '.claude', 'settings.json'), JSON.stringify({
      env: Object.fromEntries(hexKeys.map((k, i) => [`KEY_${i}_API_KEY`, k])),
      tls: { key: `-----BEGIN PRIVATE KEY-----\n${pemBody}\n-----END PRIVATE KEY-----\n` },
    }, null, 2));
    await writeFile(join(work, 'manifest.json'), JSON.stringify({ filePaths: [join(h, '.claude', 'settings.json')], globPatterns: [], commands: [], directoryListings: [], envPrefixes: [] }));
    const runs = 40;
    let pemSame = 0;
    let edgeSame = 0;
    for (let n = 0; n < runs; n++) {
      const r = await run(probe, ['--manifest', join(work, 'manifest.json')], { HOME: h, PATH: '/usr/bin:/bin', TMPDIR: tmpdir() }, h);
      expect(r.code, r.stderr).toBe(0);
      const content = Object.values((JSON.parse(r.stdout) as { files: Record<string, { content?: string }> }).files)[0].content ?? '';
      const pem = /BEGIN PRIVATE KEY-----\\n([^\\]+)\\n-----END/.exec(content)?.[1] ?? '';
      expect(pem).toHaveLength(64);
      // letters and digits: + and / used to stay as they were, the rest never
      for (let i = 0; i < 64; i++) if (/[A-Za-z0-9]/.test(pemBody[i]) && pem[i] === pemBody[i]) pemSame++;
      for (const k of hexKeys) {
        const d = new RegExp(`${k.slice(0, 8)}([0-9a-f]{28})${k.slice(-4)}`).exec(content)?.[1];
        expect(d, k).toBeDefined();
        // the first and last hidden characters
        if (d![0] === k[8]) edgeSame++;
        if (d![27] === k[35]) edgeSame++;
      }
    }
    // chance: 1 in 64 for a PEM character (about 40 in 40 snapshots), about 1 in 10
    // for a hex edge (about 96 of 960); excluding the original gives 0
    expect(pemSame).toBeGreaterThan(10);
    expect(edgeSame).toBeGreaterThan(20);
  }, 300_000);

  it('keeps no more of a hex key than chance', () => {
    // a stand-in keeps the first 8 and last 4 characters; of the 28 between,
    // a random hex character matches 1 time in 6 or 10 — a substitution
    // keeping every symbol the head and tail show kept about two thirds
    let same = 0;
    let total = 0;
    for (const v of hexCanaries) {
      const re = new RegExp(`${v.slice(0, 8)}([0-9a-f]{28})${v.slice(-4)}`, 'g');
      for (const m of haystack.matchAll(re)) {
        for (let i = 0; i < 28; i++) if (m[1][i] === v[8 + i]) same++;
        total += 28;
      }
    }
    expect(total).toBeGreaterThan(28 * 100);
    expect(same / total).toBeLessThan(0.3);
  });
});
