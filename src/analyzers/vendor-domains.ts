/**
 * Where a vendor's API credential is supposed to go. Shared by the JS and
 * Python data-flow analyzers: an environment value named for a vendor
 * (`OPENAI_API_KEY`) in the headers of a request to that vendor's own https
 * API is how the key is used, not a leak.
 */
import { isSecretName } from '../reporting/serialize.js';

/**
 * The API domains a vendor's credential is used against, by the env-name
 * prefix that names the vendor. Only these are exempt: a host merely
 * containing the vendor's name (api.openai.cc, openai.vercel.app) is not.
 */
export const VENDOR_API_DOMAINS: Record<string, readonly string[]> = {
  openai: ['openai.com'],
  anthropic: ['anthropic.com'],
  claude: ['anthropic.com'],
  github: ['github.com'],
  gh: ['github.com'],
  gitlab: ['gitlab.com'],
  slack: ['slack.com'],
  stripe: ['stripe.com'],
  groq: ['groq.com'],
  mistral: ['mistral.ai'],
  huggingface: ['huggingface.co'],
  hf: ['huggingface.co'],
  gemini: ['googleapis.com'],
  google: ['googleapis.com'],
  cohere: ['cohere.ai', 'cohere.com'],
  deepseek: ['deepseek.com'],
  perplexity: ['perplexity.ai'],
  pplx: ['perplexity.ai'],
  xai: ['x.ai'],
  openrouter: ['openrouter.ai'],
  together: ['together.xyz', 'together.ai'],
  fireworks: ['fireworks.ai'],
  replicate: ['replicate.com'],
  notion: ['notion.com'],
  linear: ['linear.app'],
  discord: ['discord.com'],
  telegram: ['telegram.org'],
  brave: ['brave.com'],
  tavily: ['tavily.com'],
  exa: ['exa.ai'],
  firecrawl: ['firecrawl.dev'],
  serpapi: ['serpapi.com'],
  elevenlabs: ['elevenlabs.io'],
  sentry: ['sentry.io'],
  vercel: ['vercel.com'],
  cloudflare: ['cloudflare.com'],
  supabase: ['supabase.com'],
  // Jira / Confluence Cloud: Basic auth (email:API token) to the site's own *.atlassian.net
  jira: ['atlassian.net'],
  atlassian: ['atlassian.net'],
  confluence: ['atlassian.net'],
};

/**
 * Where a vendor documents putting its key in the URL itself, on its own
 * https host: Google API keys as `?key=` (ai.google.dev, *.googleapis.com),
 * SerpApi's `?api_key=`, a Telegram bot token as the `/bot<token>/` path of
 * api.telegram.org. Anywhere else in a URL — or on any other host — the key
 * is leaving.
 */
const VENDOR_URL_SLOTS: Record<string, { query?: readonly string[]; botPath?: boolean }> = {
  google: { query: ['key'] },
  gemini: { query: ['key'] },
  serpapi: { query: ['api_key'] },
  telegram: { botPath: true },
};

/** The API domains the credential in environment variable `envName` belongs to (`OPENAI_…` → openai.com). */
export function vendorApiDomains(envName: string | undefined): readonly string[] | undefined {
  const vendor = envName?.split('_')[0]?.toLowerCase() ?? '';
  return Object.hasOwn(VENDOR_API_DOMAINS, vendor) ? VENDOR_API_DOMAINS[vendor] : undefined;
}

/**
 * Whether a value written into a URL right after `before` (the URL's static
 * text up to it) sits where the vendor of `envName` documents its key:
 * `…?key=` / `…&key=` for Google, `https://api.telegram.org/bot` for Telegram.
 */
export function vendorUrlSlot(envName: string | undefined, before: string): boolean {
  const vendor = envName?.split('_')[0]?.toLowerCase() ?? '';
  const slot = Object.hasOwn(VENDOR_URL_SLOTS, vendor) ? VENDOR_URL_SLOTS[vendor] : undefined;
  if (!slot) return false;
  // Telegram: /bot<token>/method and the file download /file/bot<token>/path
  if (slot.botPath && /^https:\/\/[^/?#@]+\/(?:file\/)?bot$/i.test(before)) return true;
  // a query key on a storage host lands in the bucket owner's access logs
  const host = /^https:\/\/([^/?#@]+)/i.exec(before)?.[1]?.toLowerCase() ?? '';
  if (/^(?:storage|storage-download|firebasestorage)\./.test(host) || host === 'storage.cloud.google.com') return false;
  const query = /[?&]([A-Za-z_]+)=$/.exec(before);
  return query !== null && before.includes('?') && (slot.query ?? []).includes(query[1]);
}

/**
 * The scheme and host a URL's static start fixes (`https://api.telegram.org/`),
 * when the text before its first computed part already ends the host — a
 * value spliced into the host itself (`https://api.openai.com${x}`) could take
 * the request anywhere.
 */
export function staticOrigin(prefix: string): string | undefined {
  return /^https:\/\/[^/?#@\s]+[/?#]/i.exec(prefix)?.[0];
}

/** Whether `url` is an https URL on one of `domains` (or a subdomain) — a lookalike host is not. */
export function onVendorHost(url: string | undefined, domains: readonly string[]): boolean {
  try {
    const parsed = new URL(url ?? '');
    if (parsed.protocol !== 'https:') return false;
    const host = parsed.hostname.toLowerCase();
    return domains.some((d) => host === d || host.endsWith(`.${d}`));
  } catch {
    return false;
  }
}

/** Connection strings carry a password: `DATABASE_URL`, `REDIS_URL`, `SENTRY_DSN`. */
const CONNECTION_STRING_NAME = /(?:^|_)(?:DSN|(?:DATABASE|DB|REDIS|MONGO(?:DB)?|POSTGRES(?:QL)?|PG|MYSQL|AMQP|RABBITMQ|BROKER)_?UR[LI])$/i;

/**
 * Whether an environment variable holds a credential by its name
 * (`AWS_SECRET_ACCESS_KEY`, `GH_TOKEN`, `DATABASE_URL`) — not a setting such
 * as `HOME`, `NODE_ENV`, `PORT` or `API_BASE_URL`.
 */
export function credentialEnvName(name: string): boolean {
  return isSecretName(name) || CONNECTION_STRING_NAME.test(name);
}

/**
 * Credentials never sent as they are, to anyone: they sign or encrypt
 * (AWS secret keys, private keys, session/JWT/cookie/webhook signing
 * secrets, HMAC and encryption keys, Django's `SECRET_KEY`).
 */
const SIGNING_SECRET_NAME = /(?:^|_)(?:SECRET_ACCESS_KEY|PRIVATE_KEY|SIGNING_(?:KEY|SECRET)|(?:SESSION|JWT|COOKIE|WEBHOOK|NEXTAUTH|AUTH|HMAC|APP|ENCRYPTION|SIGNATURE)_SECRET(?:_KEY)?|(?:HMAC|ENCRYPTION|JWT|SESSION|COOKIE)_KEY)$|^SECRET_KEY(?:_BASE)?$|^(?:HMAC|SIGNING)_/i;

/** A credential that signs or encrypts — sent in any request, headers included, it is leaving. */
export function signingSecret(name: string | undefined): boolean {
  return name !== undefined && SIGNING_SECRET_NAME.test(name);
}

/**
 * Database and broker credentials (`DB_PASSWORD`, `PGPASSWORD`,
 * `MYSQL_ROOT_PASSWORD`, `DATABASE_URL`): their home is a database
 * connection, never the headers or URL of an HTTP request.
 */
const STORE_CREDENTIAL_NAME = /^(?:PGPASSWORD|PGPASSFILE)$|(?:^|_)(?:DB|DATABASE|PG|POSTGRES(?:QL)?|MYSQL|MARIADB|MONGO(?:DB)?|REDIS|MSSQL|SQLSERVER|ORACLE|CLICKHOUSE|ELASTIC(?:SEARCH)?|RABBITMQ|AMQP|NEO4J|CASSANDRA|COUCHDB)_(?:[A-Z0-9]+_)*(?:PASS(?:WORD)?|PASSWD|PWD)$/i;

/**
 * A credential whose rightful destination is known: a vendor's key
 * (`OPENAI_API_KEY` → openai.com, `GH_TOKEN` → github.com), a signing
 * secret that goes nowhere, or a database credential (its connection). Sent outside a request body — in its URL,
 * headers, query, auth or cookies — anywhere but the vendor's own API
 * headers, it is leaving. A generic `API_KEY` or `TOKEN` in a request's
 * headers is how the skill authenticates to whatever API it calls.
 */
export function ownedCredential(name: string | undefined): boolean {
  if (name === undefined || !credentialEnvName(name)) return false;
  return vendorApiDomains(name) !== undefined || SIGNING_SECRET_NAME.test(name) || STORE_CREDENTIAL_NAME.test(name)
    || CONNECTION_STRING_NAME.test(name);
}
