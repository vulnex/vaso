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

End users can override them with `vaso update --url <url>` (IOC feed) and `vaso update --advisory-url <url>` (advisory feed). The override must still verify against the pinned key.

## How merging works

VASO ships with bundled IOC and advisory data baked into every release. The feeds are **cumulative**, not deltas: each version carries every published entry, and at release time the bundled data equals the signed feeds (a unit test enforces this). Between releases a newer feed adds what surfaced since. The client merges the cached feed on top of the bundled data, deduplicating exact matches, so bundled coverage is the floor and the feed only ever adds to it. Clients accept only a feed version newer than the one they have cached (`vaso update --force` re-installs the same version, never an older one).

Advisories merge by `id`: a feed advisory overrides a bundled one with the same `id` (used to ship CVE corrections without a VASO release).

## Updating the feed

See the maintainer runbook (kept locally, not in the public repo). Brief summary: edit the JSON, increment `meta.version`, re-sign with `node scripts/sign-feed.mjs <file> <private-key.pem>`, commit, push.
