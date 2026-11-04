import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { DATA_FILES, USER_DATA_FILES } from '../../adapters/grok-bot.js';
import { dataFile, userDataDir } from './shared.js';

/**
 * How Grok Bot protects what it stores (0.71.2):
 * - The local-exec credential and connection files are sealed with AES-256-GCM
 *   under a key kept in sand-secrets.json: { "sandSealedFile": 1, "data": … }.
 *   Without OS secure storage the app writes them as plain JSON — a bearer
 *   credential for the channel the cloud agent uses to run commands here.
 * - sand-secrets.json (Cursor access/refresh tokens, the seal key) and
 *   user-secrets.json hold base64(safeStorage.encryptString(v)), optionally
 *   prefixed `scoped:v1:<64 hex>:`. `plaintext:v1:` marks an unencrypted value
 *   (a legacy format 0.71.2 still reads and re-encrypts, but no longer writes);
 *   on Linux a `v10` blob (base64 `djEw`) comes from the basic_text backend,
 *   encrypted under Chromium's fixed, public key.
 * - host-token.json ({ accessToken }, 0.78) holds the account's access token in
 *   plaintext. Only unpackaged (development) builds write it, refreshing it
 *   every minute; a released install never has one.
 * Only prefixes are inspected — values never reach evidence. Remote scans
 * don't collect these files, so the check runs on local scans only.
 */
const SCOPED = /^scoped:v1:[0-9a-f]{64}:/;
const PLAINTEXT = 'plaintext:v1:';
const V10 = 'djEw';

type Protection = 'plaintext' | 'v10' | 'ok';

function protection(value: unknown): Protection | undefined {
  if (typeof value !== 'string' || value === '') return undefined;
  const v = value.replace(SCOPED, '');
  if (v.startsWith(PLAINTEXT)) return 'plaintext';
  if (v.startsWith(V10)) return 'v10';
  return 'ok';
}

const SECRET_KEY = /token|secret|key|password/i;

/**
 * Values to judge, one per stored secret. `cursor-accounts` is a JSON document
 * ({ active, accounts: { <scope>: { cursor-access-token, … } } }) — normally
 * encrypted as a whole; stored as raw JSON its tokens sit in it unless each is
 * encrypted itself, so a raw token there is plaintext.
 */
function secretValues(value: unknown): unknown[] {
  if (typeof value !== 'string' || !value.trimStart().startsWith('{')) return [value];
  let doc: unknown;
  try {
    doc = JSON.parse(value);
  } catch {
    return [value];
  }
  const out: unknown[] = [];
  const walk = (node: unknown, key: string, depth: number) => {
    if (depth > 6) return;
    if (typeof node === 'string') {
      if (SECRET_KEY.test(key) && node) out.push(protection(node) === 'ok' && !/^djE[wx]/.test(node) ? `${PLAINTEXT}${node}` : node);
    } else if (node && typeof node === 'object') {
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) walk(v, k, depth + 1);
    }
  };
  walk(doc, '', 0);
  return out;
}

async function readJson(ctx: ScanContext, path: string): Promise<{ data?: unknown; unread?: boolean }> {
  if (!(await ctx.fs.access(path))) return {};
  try {
    return { data: JSON.parse(await ctx.fs.readFile(path)) };
  } catch (err) {
    // Not shipped by the probe, or unreadable — say so rather than pass silently
    return { unread: !(err instanceof SyntaxError) };
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

export const gb006 = defineCheck({
  id: 'GB-006',
  name: 'Grok Bot Credentials Without OS Keyring Protection',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect Grok Bot credentials stored in plaintext or under Chromium\'s fixed Linux key: an unsealed local-exec credential/connection file (bearer access to the channel the cloud agent runs commands through), or sand-secrets.json / user-secrets.json values marked plaintext:v1: or encrypted with the basic_text (v10) backend',
  supportedAgents: ['grok-bot'],

  async run(ctx, h) {
    const critical: Evidence[] = [];
    const warning: Evidence[] = [];
    const unread: string[] = [];

    for (const name of [DATA_FILES.credential, DATA_FILES.connection]) {
      const file = dataFile(ctx, name);
      const { data, unread: u } = await readJson(ctx, file);
      if (u) unread.push(file);
      if (!isRecord(data) || data.sandSealedFile === 1) continue;
      critical.push({ file, snippet: 'no "sandSealedFile" envelope', detail: 'Stored as plain JSON — anyone who reads it can impersonate this computer to the Grok Bot backend' });
    }

    // Present at all means a development build ran here; remote scans see it
    // exists without its content, which is enough
    const hostToken = dataFile(ctx, DATA_FILES.hostToken);
    const token = await readJson(ctx, hostToken);
    if (token.unread || (isRecord(token.data) && typeof token.data.accessToken === 'string' && token.data.accessToken !== '')) {
      critical.push({ file: hostToken, snippet: 'accessToken (plaintext)', detail: 'The Cursor account access token in plain JSON, written by an unpackaged (development) Grok Bot build — delete it and run a released build' });
    }

    const tally = (file: string, values: unknown[], holds: string) => {
      const counts = { plaintext: 0, v10: 0 };
      for (const v of values.flatMap(secretValues)) {
        const p = protection(v);
        if (p === 'plaintext' || p === 'v10') counts[p]++;
      }
      if (counts.plaintext > 0) {
        critical.push({ file, snippet: `${counts.plaintext} value(s) "plaintext:v1:"`, detail: `${holds} stored unencrypted (no OS secure storage when written)` });
      }
      if (counts.v10 > 0 && ctx.fs.platform === 'linux') {
        warning.push({ file, snippet: `${counts.v10} value(s) safeStorage v10`, detail: `${holds} encrypted with Chromium's fixed basic_text key — no keyring was available; any reader can decrypt them` });
      }
    };

    const userData = await userDataDir(ctx);
    const secretsFile = join(userData, USER_DATA_FILES.secrets);
    const secrets = await readJson(ctx, secretsFile);
    if (secrets.unread) unread.push(secretsFile);
    if (isRecord(secrets.data)) {
      tally(secretsFile, Object.entries(secrets.data).filter(([k]) => k !== 'version').map(([, v]) => v), 'Cursor account tokens / the local-exec seal key');
    }

    const userSecretsFile = join(userData, USER_DATA_FILES.userSecrets);
    const userSecrets = await readJson(ctx, userSecretsFile);
    if (userSecrets.unread) unread.push(userSecretsFile);
    if (isRecord(userSecrets.data)) {
      const values: unknown[] = [];
      const d = userSecrets.data;
      if (isRecord(d.secrets)) values.push(...Object.values(d.secrets));
      if (isRecord(d.accounts)) for (const a of Object.values(d.accounts)) if (isRecord(a)) values.push(...Object.values(a));
      tally(userSecretsFile, values, 'User-defined secrets (shared with the cloud computer)');
    }

    if (critical.length === 0 && warning.length === 0 && unread.length > 0) {
      return h.passed(`Grok Bot credential stores not inspected (${unread.length} file(s) not readable here — remote scans collect metadata only)`);
    }
    return h.fromEvidence([...critical, ...warning], {
      passed: 'Grok Bot credentials are sealed and keyring-encrypted',
      failed: (n) => `Found ${n} Grok Bot credential store(s) without OS keyring protection`,
      severity: critical.length > 0 || warning.length === 0 ? undefined : 'warning',
      fixDescription: 'Run Grok Bot with a working OS keyring (gnome-keyring / KWallet on Linux), then sign out and back in so tokens and the local-exec credential are re-written sealed',
    });
  },
});
