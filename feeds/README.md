# Published threat feeds

VASO clients fetch these files via `vaso update`:

| File | Purpose |
|------|---------|
| `feed.json` | IOC feed (C2 IPs, malicious domains, hashes, publishers, skill patterns, MCP packages, binary patterns) |
| `feed.json.sig` | Base64-encoded Ed25519 signature over the raw bytes of `feed.json` |
| `advisory-feed.json` | Version-aware vulnerability advisories |
| `advisory-feed.json.sig` | Base64-encoded Ed25519 signature over `advisory-feed.json` |

The signing **public key is pinned** in the released VASO binary at `src/ioc/public-key.ts`. Clients reject any feed that does not verify against that key — there is no TOFU and rotation requires a VASO release.

## URLs

- IOC feed: `https://raw.githubusercontent.com/vulnex/vaso/main/feeds/feed.json` (+ `.sig`)
- Advisory feed: `https://raw.githubusercontent.com/vulnex/vaso/main/feeds/advisory-feed.json` (+ `.sig`)

End users can override with `vaso update --url <url>`.

## How merging works

VASO ships with bundled IOC and advisory data baked into every release. These feed files carry **deltas only** — new threats that surfaced after the release was cut. The client merges feed on top of bundled, deduplicating exact matches. Bundled coverage is the floor; the feed only ever adds to it.

Advisories merge by `id`: a feed advisory overrides a bundled one with the same `id` (used to ship CVE corrections without a VASO release).

## Updating the feed

See the maintainer runbook (kept locally, not in the public repo). Brief summary: edit the JSON, increment `meta.version`, re-sign with `node scripts/sign-feed.mjs <file> <private-key.pem>`, commit, push.
