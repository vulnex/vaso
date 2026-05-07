function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * IPv4 boundary: surrounding chars must not be digit or dot, so `1.2.3.4`
 * does not match inside `1.2.3.40`, `11.2.3.4`, or `1.2.3.4.5`. The current
 * IOC database holds only IPv4 addresses; extend boundary chars if IPv6
 * IOCs are ever added.
 */
export function ipBoundaryRegex(ip: string): RegExp {
  return new RegExp(`(?<![\\d.])${escapeRegex(ip)}(?![\\d.])`);
}

/**
 * Hostname boundary: the IOC matches as a full domain or as a suffix on a
 * subdomain. `evil.com` matches `evil.com` and `bad.evil.com`, but not
 * `notevil.com` (left boundary blocks letter/digit/hyphen) or
 * `evil.commerce.org` / `evil.com.cn` (right boundary blocks
 * letter/digit/dot/hyphen, where dot would mean another label follows).
 * Case-insensitive per DNS.
 */
export function domainBoundaryRegex(domain: string): RegExp {
  return new RegExp(`(?<![a-zA-Z0-9-])${escapeRegex(domain)}(?![a-zA-Z0-9.-])`, 'i');
}
