/**
 * The registrable domain of a host name — the part someone registered — and
 * its distinguishing label, without the full Public Suffix List
 * (publicsuffix.org). `agenthub.contetial.com` was registered as
 * `contetial.com`: `agenthub` is a subdomain its owner picked, a word anyone
 * may use in a package name. On a shared hosting platform the tenant name is
 * the registration (`openclawcli.vercel.app`, PSL's private section).
 *
 * The suffix list below is the multi-label part of the PSL that matters for
 * threat-intel domains: country second levels (`co.uk`, `com.cn`) and the
 * hosting platforms free C2s and payload hosts use. A suffix not on it is
 * taken to be the last label (`.com`, `.cn`, `.su`), which is right for every
 * single-label TLD. Matching is longest-suffix-first, like the PSL algorithm.
 */
const MULTI_LABEL_SUFFIXES = new Set([
  // Country second levels (ICANN section)
  'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'ac.uk', 'gov.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au',
  'co.nz', 'net.nz', 'org.nz',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp', 'gr.jp',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
  'com.hk', 'net.hk', 'org.hk', 'com.tw', 'net.tw', 'org.tw', 'com.sg', 'com.my', 'co.kr', 'or.kr', 'ne.kr',
  'co.in', 'net.in', 'org.in', 'firm.in', 'gen.in', 'ind.in',
  'com.br', 'net.br', 'org.br', 'com.ar', 'com.mx', 'com.co', 'com.pe', 'com.ve',
  'co.za', 'org.za', 'com.ng', 'com.eg', 'co.ke',
  'com.tr', 'net.tr', 'org.tr', 'com.ua', 'org.ua', 'co.il', 'org.il', 'com.sa', 'com.pk', 'com.vn', 'com.ph', 'co.id', 'co.th', 'in.th',
  'com.ru', 'net.ru', 'org.ru', 'msk.ru', 'spb.ru',
  'com.pl', 'net.pl', 'org.pl', 'com.es', 'co.it', 'com.pt', 'co.at', 'or.at',
  // Hosting platforms (private section): the tenant name is the registration
  'vercel.app', 'now.sh', 'netlify.app', 'netlify.com', 'pages.dev', 'workers.dev', 'fly.dev', 'onrender.com',
  'herokuapp.com', 'github.io', 'gitlab.io', 'glitch.me', 'repl.co', 'replit.app', 'replit.dev', 'web.app', 'firebaseapp.com',
  'azurewebsites.net', 'cloudfront.net', 'appspot.com', 'blogspot.com', 'surge.sh', 'deno.dev', 'railway.app', 'up.railway.app',
  'ngrok.io', 'ngrok-free.app', 'ngrok.app', 'trycloudflare.com', 'loca.lt', 'serveo.net', 'duckdns.org', 'no-ip.org', 'ddns.net',
]);

/** `contetial.com` for `agenthub.contetial.com`; undefined for a bare suffix or an IP address. */
export function registrableDomain(host: string): string | undefined {
  const h = host.trim().toLowerCase().replace(/\.$/, '');
  if (!h || /^[\d.]+$/.test(h) || h.includes(':')) return undefined;
  const labels = h.split('.');
  // Longest listed suffix; else the TLD alone
  let suffixLength = 1;
  for (let k = Math.min(labels.length, 3); k >= 2; k--) {
    if (MULTI_LABEL_SUFFIXES.has(labels.slice(-k).join('.'))) { suffixLength = k; break; }
  }
  if (labels.length <= suffixLength) return undefined;
  return labels.slice(-(suffixLength + 1)).join('.');
}

/** The registered name's own label: `contetial` for `agenthub.contetial.com`, `openclawcli` for `openclawcli.vercel.app`. */
export function registrableLabel(host: string): string | undefined {
  return registrableDomain(host)?.split('.')[0];
}
