/**
 * Bundled Ed25519 public key for IOC feed signature verification.
 *
 * Generated via: node scripts/generate-feed-keypair.mjs
 * Key rotation requires a new VASO release (key pinning, no TOFU).
 */
export const IOC_FEED_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAbQYvc5oC7DEniTTdm2Qupa7OV6zPasSfjabs5Hik5LI=
-----END PUBLIC KEY-----`;

/** Default feed URL — can be overridden via --url */
export const DEFAULT_FEED_URL = 'https://raw.githubusercontent.com/vulnex/vaso-feeds/main/feed.json';

/** Default staleness threshold in days */
export const DEFAULT_STALENESS_DAYS = 7;
