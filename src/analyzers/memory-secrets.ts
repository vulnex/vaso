import type { Evidence, Severity } from '../core/types.js';
import { API_KEY_PATTERNS, isPlaceholderSecret, isSecretReference, secretShape } from '../core/patterns.js';
import { findHighEntropyBlocks } from './entropy.js';
import { isCredentialValueName, isHashedValue, isKnownSecretValue, looksRandom } from './secret-values.js';

/**
 * Plaintext-secret scan for the prose files coding agents load into every
 * prompt (CLAUDE.md, AGENTS.md, GEMINI.md, QWEN.md, copilot-instructions.md,
 * Devin rules files). Shared by CC-012, CDX-007, OPC-007, GEM-010, QC-010,
 * GHC-008 and DEV-007 so every agent recognises the same key formats —
 * including OpenAI's `sk-proj-`/`sk-svcacct-`/`sk-admin-` keys from
 * `API_KEY_PATTERNS`.
 *
 * Tiering (one rule for all memory checks): a recognised credential format
 * is critical — a live key sits in a file that is sent to the model and is
 * routinely committed; a high-entropy string with no known prefix, or a
 * random-looking value written under a credential name (`DB_PASSWORD=…`,
 * `api_key: …`, `Authorization: Bearer …`), is only a possible secret,
 * reported as a warning.
 */

/** Formats `API_KEY_PATTERNS` doesn't cover. */
const EXTRA_KEY_PATTERNS: { pattern: RegExp; name: string }[] = [
  { pattern: /github_pat_[A-Za-z0-9_]{20,}/, name: 'GitHub fine-grained PAT' },
  { pattern: /AIza[0-9A-Za-z_-]{30,}/, name: 'Google API key' },
  { pattern: /xox[aprs]-[A-Za-z0-9-]{10,}/, name: 'Slack token' },
  { pattern: /pat[A-Za-z0-9]{14}\.[0-9a-f]{64}/, name: 'Airtable personal access token' },
];

// In prose a key starts at a word boundary: `disk-0123…` is not an `sk-` key.
// A lookbehind (not \b) so patterns starting with `-` keep matching.
const KNOWN_KEY_PATTERNS = [...API_KEY_PATTERNS, ...EXTRA_KEY_PATTERNS].map(({ pattern, name }) => ({
  pattern: new RegExp(`(?<![A-Za-z0-9_])(?:${pattern.source})`, pattern.flags),
  name,
}));

/**
 * `name: value` / `name = value` / `| name | value |` in prose, the name a
 * credential word (up to three words: `**API key**: …`, `**API key:** …`), the value one
 * unbroken run that isn't a call (`token = getToken(…)`). Quotes, `**`
 * emphasis and backticks around either are allowed;
 * `Authorization: Bearer x` carries the value after the scheme.
 */
const KEYED_VALUE = /(?<![A-Za-z0-9_])([A-Za-z][\w.-]{0,63}(?: [A-Za-z][\w.-]{0,31}){0,2})["'`*]*[ \t]*(?:[:=]|\|)\*{0,2}[ \t]*(?:"([^"\n]{12,256})"|'([^'\n]{12,256})'|`([^`\n]{12,256})`|["'`]?(?:(?:bearer|basic|token)[ \t]+)?([^\s"'`|,;(){}[\]<>]{12,}))/gi;
const CREDENTIAL_NAME = /(?:password|passwd|passphrase|pwd|secret|token|api[ _-]?key|apikey|private[ _-]?key|access[ _-]?key|credential|bearer|authorization|(?:^|[ _-])(?:key|pat|auth)$)/i;
/**
 * "… key" names that hold an identifier by meaning (`Idempotency key`,
 * `Cache key`, `Partition key`, `S3 key` — an object path): the value is an
 * ID. Not `Primary key`, `Storage key`, `Blob key` …: Azure calls its
 * account access keys exactly that. Even under these names a value shaped
 * like a key (STRONG_KEY_VALUE) is still reported.
 */
const IDENTIFIER_KEY_NAME = /(?:^|[ _-])(?:idempotency|cache|s3|partition|sort|foreign|composite|lookup|dedup(?:lication)?|routing|shard(?:ing)?|i18n|translation)[ _-]?key$/i;
/** 32+ hex digits, or 40+ characters of base64 with its punctuation: a key whatever it is called. */
const STRONG_KEY_VALUE = /^(?:[0-9a-f]{32,}|[0-9A-F]{32,}|(?=[A-Za-z0-9+/]*[+/])[A-Za-z0-9+/]{40,}={0,2}|[A-Za-z0-9+/]{40,}={1,2})$/;

/** The first keyed credential on a line: a credential name with a random-looking value. */
function keyedSecret(line: string): { name: string; value: string } | undefined {
  for (const m of line.matchAll(KEYED_VALUE)) {
    // `export GITHUB_TOKEN=…`: the shell keyword isn't part of the name
    const name = m[1].trim().replace(/^(?:export|set|setx|const|let|var|declare)\s+/, '');
    // a quoted value runs to its closing quote (`"Ab3…;Xy9"`), an
    // `Authorization: "Bearer x"` one after its scheme
    const quoted = (m[2] ?? m[3] ?? m[4])?.replace(/^(?:bearer|basic|token)\s+/i, '');
    const value = quoted ?? m[5];
    // one space inside quotes doesn't make a random value prose
    const judged = quoted !== undefined && (quoted.match(/ /g) ?? []).length === 1 ? quoted.replace(' ', '') : value;
    // the whole run, not a prefix of `getToken(…)` the regex backed off to
    if (/[(\[{]/.test(line[(m.index ?? 0) + m[0].length] ?? '')) continue;
    // `See the token docs: https://…` names a document, `$TOKEN`/`op://…` where the secret is kept
    if (!CREDENTIAL_NAME.test(name) || !isCredentialValueName(name.replace(/ /g, '_'))) continue;
    if (IDENTIFIER_KEY_NAME.test(name) && !STRONG_KEY_VALUE.test(value) && !isKnownSecretValue(value)) continue;
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value) || isPlaceholderSecret(value) || isSecretReference(value) || isHashedValue(value)) continue;
    if (isKnownSecretValue(value) || looksRandom(judged, 12)) return { name, value };
  }
  return undefined;
}

const ENTROPY_THRESHOLD = 5.5;
const MIN_BLOCK_LEN = 40;

/** Evidence items that are a recognised credential (vs. a high-entropy guess). */
const CREDENTIAL_EVIDENCE = new WeakSet<Evidence>();

/** Evidence for every plaintext credential (one per line) and high-entropy string in `content`. */
export function scanMemorySecrets(file: string, content: string, kind = 'memory file'): Evidence[] {
  const evidence: Evidence[] = [];
  // one finding per line, looked up per line: a list scan was quadratic
  const reported = new Set<number>();
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    for (const { pattern, name } of KNOWN_KEY_PATTERNS) {
      const m = pattern.exec(lines[i]);
      if (!m || isPlaceholderSecret(m[0])) continue;
      const item: Evidence = {
        file,
        line: i + 1,
        // no more of a key than reports show anywhere (8 characters)
        snippet: `${m[0].slice(0, 4)}…${m[0].slice(-4)} (${m[0].length} chars)`,
        detail: `Plaintext ${name} in ${kind}`,
      };
      CREDENTIAL_EVIDENCE.add(item);
      evidence.push(item);
      reported.add(i + 1);
      break;
    }
  }

  for (let i = 0; i < lines.length; i++) {
    if (reported.has(i + 1)) continue;
    const keyed = keyedSecret(lines[i]);
    if (!keyed) continue;
    const v = keyed.value;
    reported.add(i + 1);
    evidence.push({
      file,
      line: i + 1,
      // the value itself is never quoted
      snippet: `${keyed.name}: ${secretShape(v)}`,
      detail: `Plaintext value under "${keyed.name}" — looks like a credential (random, not a reference or placeholder)`,
    });
  }

  // `* item` bullets are prose here, not the `*` of a block comment the
  // entropy scan skips
  const prose = content.replace(/^([ \t]*)\*(?=[ \t])/gm, '$1-');
  for (const b of findHighEntropyBlocks(prose, ENTROPY_THRESHOLD, MIN_BLOCK_LEN)) {
    if (reported.has(b.line)) continue;
    reported.add(b.line);
    evidence.push({
      file,
      line: b.line,
      snippet: b.snippet,
      detail: `High-entropy string (${b.entropy} bits) — possible embedded secret`,
    });
  }
  return evidence;
}

/** Critical when a live (unmitigated) item is a recognised credential, else warning. */
export function memorySecretSeverity(evidence: Evidence[]): Severity {
  return evidence.some(e => !e.mitigated && CREDENTIAL_EVIDENCE.has(e)) ? 'critical' : 'warning';
}
