function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * A dot that starts another label (`.5`, `.example`) — not one that ends a
 * sentence (`… 1.2.3.4.`) or a fully-qualified name (`https://evil.com./x`).
 */
const NEXT_LABEL = String.raw`\.[a-zA-Z0-9_-]`;

/**
 * IPv4 boundary: the preceding char must not be digit or dot, and the
 * following one not a digit or a dot that starts another label, so
 * `1.2.3.4` does not match inside `1.2.3.40`, `11.2.3.4`, `1.2.3.4.5` or
 * the hostname `1.2.3.4.example`, but does at a sentence end (`1.2.3.4.`).
 * The current IOC database holds only IPv4 addresses; extend boundary chars
 * if IPv6 IOCs are ever added.
 */
export function ipBoundaryRegex(ip: string): RegExp {
  return new RegExp(`(?<![\\d.])${escapeRegex(ip)}(?!\\d)(?!${NEXT_LABEL})`);
}

/**
 * Hostname boundary: the IOC matches as a full domain or as a suffix on a
 * subdomain. `evil.com` matches `evil.com` and `bad.evil.com`, but not
 * `notevil.com` (left boundary blocks letter/digit/hyphen) or
 * `evil.commerce.org` / `evil.com.cn` (right boundary blocks
 * letter/digit/hyphen, and a dot that starts another label). A trailing dot
 * that starts nothing — a sentence end (`evil.com.`) or the fully-qualified
 * form (`https://evil.com./x`) — still matches. Case-insensitive per DNS.
 */
export function domainBoundaryRegex(domain: string): RegExp {
  return new RegExp(`(?<![a-zA-Z0-9-])${escapeRegex(domain)}(?![a-zA-Z0-9-])(?!${NEXT_LABEL})`, 'i');
}
