/**
 * Listen addresses that mean "every interface". A config can spell the
 * unspecified address many ways and the socket layer accepts them all:
 * `0.0.0.0`, `0` (inet_aton), `000.0.0.0`, `::`, `::0`, `[::]`,
 * `0:0:0:0:0:0:0:0`, `0000:0000::`, plus `*` for listeners that take it.
 * One normaliser, so no check reads one of these as a specific host.
 */

/** Options for {@link isWildcardAddress}. */
export interface WildcardOptions {
  /**
   * An empty host binds every interface (Python asyncio `create_server`,
   * Node `server.listen(port, '')`). Off by default: in most configs an
   * empty host means "unset", and the listener falls back to its default.
   */
  emptyIsWildcard?: boolean;
}

/**
 * An IPv4 address as inet_aton reads it (Python and Node resolve listen
 * hosts through it): one to four parts, each decimal, `0x` hex or
 * 0-prefixed octal, the last part filling the remaining bytes — so `127.1`,
 * `0x7f.1` and `2130706433` are 127.0.0.1. Undefined when not one.
 */
function inetAton(h: string): number | undefined {
  const parts = h.split('.');
  if (parts.length > 4) return undefined;
  const nums: number[] = [];
  for (const p of parts) {
    let n: number;
    if (/^0x[0-9a-f]*$/i.test(p)) n = p.length === 2 ? 0 : parseInt(p.slice(2), 16);
    else if (/^0[0-7]*$/.test(p)) n = parseInt(p, 8);
    else if (/^[1-9]\d*$/.test(p)) n = parseInt(p, 10);
    else return undefined;
    nums.push(n);
  }
  const last = nums.pop()!;
  if (nums.some(n => n > 255) || last >= 2 ** (8 * (4 - nums.length))) return undefined;
  return nums.reduce((acc, n, i) => acc + n * 2 ** (8 * (3 - i)), 0) + last;
}

/**
 * Whether `host` binds loopback only: `localhost` (and `*.localhost`),
 * 127.0.0.0/8 in any inet_aton spelling (`127.1`, `0x7f.1`; macOS reads a
 * leading-zero part as decimal, so `0177.0.0.1` fails to bind there and is
 * loopback on Linux — no exposure either way), `::1`, and IPv4-mapped
 * `::ffff:127.x` (Node binds it as loopback).
 */
export function isLoopbackAddress(host: string): boolean {
  const h = host.trim().replace(/^\[(.*)\]$/, '$1').toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  const v4 = inetAton(h);
  if (v4 !== undefined) return v4 >>> 24 === 127;
  if (!h.includes(':')) return false;
  const g = ipv6Groups(h.replace(/%[^%]*$/, ''));
  if (!g) return false;
  if (g.slice(0, 7).every(v => v === 0) && g[7] === 1) return true;
  return g.slice(0, 5).every(v => v === 0) && g[5] === 0xffff && g[6] >>> 8 === 127;
}

/**
 * IPv4 with every part zero as inet_aton reads it (Python and Node resolve
 * hosts with it): `0`, `0.0`, `0.0.0.0`, `000.0.0.0`, hex `0x0`.
 */
function zeroIPv4(h: string): boolean {
  return inetAton(h) === 0;
}

/** The eight 16-bit groups of an IPv6 address (embedded dotted IPv4 allowed); undefined when malformed. */
function ipv6Groups(addr: string): number[] | undefined {
  // A trailing dotted IPv4 (`::0.0.0.0`, `::ffff:1.2.3.4`) is the last two groups
  let text = addr;
  const dot = /:((?:\d{1,3}\.){3}\d{1,3})$/.exec(text);
  if (dot) {
    const q = dot[1].split('.').map(Number);
    if (q.some(n => n > 255)) return undefined;
    text = `${text.slice(0, dot.index + 1)}${(q[0] * 256 + q[1]).toString(16)}:${(q[2] * 256 + q[3]).toString(16)}`;
  }
  const halves = text.split('::');
  if (halves.length > 2) return undefined;
  const parse = (s: string): number[] | undefined => {
    if (s === '') return [];
    const parts = s.split(':');
    return parts.every(p => /^[0-9a-f]{1,4}$/i.test(p)) ? parts.map(p => parseInt(p, 16)) : undefined;
  };
  const head = parse(halves[0]);
  const rest = halves.length === 2 ? parse(halves[1]) : [];
  if (!head || !rest) return undefined;
  const known = head.length + rest.length;
  if (halves.length === 2 ? known > 7 : known !== 8) return undefined;
  return [...head, ...Array<number>(8 - known).fill(0), ...rest];
}

/**
 * IPv6 unspecified address in any valid spelling (`::`, `::0`, `0:0::0`,
 * `::0.0.0.0`), and the IPv4-mapped unspecified `::ffff:0.0.0.0` (Node
 * listens on `::` for it; Linux binds every IPv4 address).
 */
function zeroIPv6(h: string): boolean {
  const addr = h.replace(/%[^%]*$/, ''); // zone index (`::%eth0`)
  if (!addr.includes(':')) return false;
  const g = ipv6Groups(addr);
  if (!g) return false;
  return g.every(v => v === 0) || (g.slice(0, 5).every(v => v === 0) && g[5] === 0xffff && g[6] === 0 && g[7] === 0);
}

/**
 * Whether `host` binds every interface. IPv6 brackets and surrounding
 * whitespace around an address are ignored; a whitespace-only host is not
 * empty (asyncio fails to resolve it), so only an exactly empty one counts.
 */
export function isWildcardAddress(host: string, opts: WildcardOptions = {}): boolean {
  if (host === '') return opts.emptyIsWildcard === true;
  const h = host.trim().replace(/^\[(.*)\]$/, '$1').toLowerCase();
  if (h === '') return false;
  return h === '*' || zeroIPv4(h) || zeroIPv6(h);
}

/** `host:port` for messages, with an IPv6 host in brackets (`[::0]:8765`). */
export function hostPort(host: string, port: number | string | undefined): string {
  const h = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
  return port === undefined ? h : `${h}:${port}`;
}

/** `::` for an IPv6 spelling of the unspecified address, else `0.0.0.0` — for messages. */
export function wildcardFamilyLabel(host: string): '::' | '0.0.0.0' {
  return host.includes(':') ? '::' : '0.0.0.0';
}
