/**
 * Plaintext-transport test shared by the coding-agent MCP URL checks
 * (GEM-008, QC-007, GHC-004, CUR-006, WS-005, DEV-005). The host is compared after URL
 * parsing, never by string prefix: `http://localhost.evil.com` and
 * `http://127.0.0.1.nip.io` start like loopback but resolve anywhere, and the
 * WHATWG parser keeps IPv6 brackets in `hostname` (`[::1]`).
 */
export function isLoopbackHostname(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h === '::1') return true;
  // 127.0.0.0/8 — the parser already canonicalized short/hex forms (127.1)
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
}

/** True for an http:// URL whose host is not loopback. */
export function isPlaintextRemoteUrl(value: string): boolean {
  if (!/^http:\/\//i.test(value.trim())) return false;
  try {
    return !isLoopbackHostname(new URL(value.trim()).hostname);
  } catch {
    // Unparseable http:// URL — no host to vouch for
    return true;
  }
}
