import type { Advisory } from './advisory-types.js';

export interface AdvisoryDatabase {
  advisories: Advisory[];
}

const BUNDLED_ADVISORIES: Advisory[] = [
  // ── OpenClaw ──────────────────────────────────────────────────────
  {
    id: 'CVE-2026-40001',
    title: 'OpenClaw gateway authentication bypass',
    agent: 'openclaw',
    affectedVersions: '>=1.0.0 <1.5.3',
    fixedVersion: '1.5.3',
    severity: 'critical',
    description: 'Gateway auth middleware can be bypassed with crafted HTTP headers, allowing unauthenticated skill execution.',
    reference: 'https://github.com/vulnex/vaso-advisories/blob/main/CVE-2026-40001.md',
    published: '2026-01-15',
    exploitAvailable: true,
    tags: ['framework'],
  },
  {
    id: 'CVE-2026-40002',
    title: 'OpenClaw sub-agent config injection',
    agent: 'openclaw',
    affectedVersions: '>=1.2.0 <1.4.7',
    fixedVersion: '1.4.7',
    severity: 'warning',
    description: 'Sub-agent configuration values are not properly sanitized, allowing config injection via crafted profile names.',
    reference: 'https://github.com/vulnex/vaso-advisories/blob/main/CVE-2026-40002.md',
    published: '2026-02-01',
    tags: ['framework'],
  },
  {
    id: 'CVE-2026-40003',
    title: 'OpenClaw skill sandbox escape via symlink',
    agent: 'openclaw',
    affectedVersions: '>=1.0.0 <1.6.0',
    fixedVersion: '1.6.0',
    severity: 'critical',
    description: 'Skills can escape the sandbox by creating symlinks to files outside the workspace directory.',
    published: '2026-02-10',
    exploitAvailable: true,
    tags: ['framework'],
  },
  {
    id: 'VASO-EOL-OC-100',
    title: 'OpenClaw 0.x end-of-life',
    agent: 'openclaw',
    affectedVersions: '>=0.0.0 <1.0.0',
    severity: 'warning',
    description: 'OpenClaw 0.x is end-of-life and no longer receives security patches. Upgrade to 1.x or later.',
    published: '2025-06-01',
    eolNotice: true,
    tags: ['framework'],
  },

  // ── NanoClaw ──────────────────────────────────────────────────────
  {
    id: 'CVE-2026-40010',
    title: 'NanoClaw container mount escape',
    agent: 'nanoclaw',
    affectedVersions: '>=2.0.0 <2.3.1',
    fixedVersion: '2.3.1',
    severity: 'critical',
    description: 'Container mount allowlist can be bypassed using path traversal, allowing access to host filesystem.',
    reference: 'https://github.com/vulnex/vaso-advisories/blob/main/CVE-2026-40010.md',
    published: '2026-01-20',
    exploitAvailable: true,
    tags: ['framework'],
  },
  {
    id: 'CVE-2026-40011',
    title: 'NanoClaw env variable leak in logs',
    agent: 'nanoclaw',
    affectedVersions: '>=2.0.0 <2.2.0',
    fixedVersion: '2.2.0',
    severity: 'warning',
    description: 'Environment variables including API keys are written to debug logs in plaintext.',
    published: '2026-01-05',
    tags: ['framework'],
  },

  // ── PicoClaw ──────────────────────────────────────────────────────
  {
    id: 'CVE-2026-40020',
    title: 'PicoClaw gateway TLS downgrade',
    agent: 'picoclaw',
    affectedVersions: '>=0.1.0 <0.5.2',
    fixedVersion: '0.5.2',
    severity: 'critical',
    description: 'TLS connections can be downgraded to plaintext via MITM, exposing gateway traffic.',
    published: '2026-02-15',
    tags: ['framework'],
  },

  // ── IronClaw ──────────────────────────────────────────────────────
  {
    id: 'CVE-2026-40030',
    title: 'IronClaw TOML injection in config parser',
    agent: 'ironclaw',
    affectedVersions: '>=0.1.0 <0.4.0',
    fixedVersion: '0.4.0',
    severity: 'critical',
    description: 'TOML config parser does not properly escape user-controlled values, allowing injection of arbitrary config keys.',
    reference: 'https://github.com/vulnex/vaso-advisories/blob/main/CVE-2026-40030.md',
    published: '2026-01-10',
    exploitAvailable: true,
    tags: ['framework'],
  },
  {
    id: 'CVE-2026-40031',
    title: 'IronClaw gRPC gateway unauthenticated reflection',
    agent: 'ironclaw',
    affectedVersions: '>=0.1.0 <0.3.5',
    fixedVersion: '0.3.5',
    severity: 'warning',
    description: 'gRPC server reflection is enabled by default, leaking service and method definitions to unauthenticated clients.',
    published: '2026-02-05',
    tags: ['framework'],
  },

  // ── Nanobot ───────────────────────────────────────────────────────
  {
    id: 'CVE-2026-40040',
    title: 'Nanobot Discord message injection',
    agent: 'nanobot',
    affectedVersions: '>=1.0.0 <1.4.0',
    fixedVersion: '1.4.0',
    severity: 'critical',
    description: 'Discord message handler does not sanitize input, allowing injection of bot commands via crafted messages.',
    published: '2026-01-25',
    tags: ['framework'],
  },
  {
    id: 'CVE-2026-40041',
    title: 'Nanobot shell command filter bypass',
    agent: 'nanobot',
    affectedVersions: '>=1.0.0 <1.3.5',
    fixedVersion: '1.3.5',
    severity: 'critical',
    description: 'Shell command filter can be bypassed using backtick substitution, allowing arbitrary command execution.',
    published: '2026-02-12',
    exploitAvailable: true,
    tags: ['framework'],
  },

  // ── ZeroClaw ──────────────────────────────────────────────────────
  {
    id: 'CVE-2026-40050',
    title: 'ZeroClaw auth key leak via debug endpoint',
    agent: 'zeroclaw',
    affectedVersions: '>=0.1.0 <0.2.4',
    fixedVersion: '0.2.4',
    severity: 'critical',
    description: 'Debug endpoint exposes authentication keys in response headers when debug mode is enabled.',
    reference: 'https://github.com/vulnex/vaso-advisories/blob/main/CVE-2026-40050.md',
    published: '2026-01-30',
    exploitAvailable: true,
    tags: ['framework'],
  },
  {
    id: 'CVE-2026-40051',
    title: 'ZeroClaw Composio integration path traversal',
    agent: 'zeroclaw',
    affectedVersions: '>=0.1.0 <0.3.0',
    fixedVersion: '0.3.0',
    severity: 'warning',
    description: 'Composio tool integration allows path traversal in tool names, enabling access to files outside the workspace.',
    published: '2026-02-08',
    tags: ['framework'],
  },

  // ── Dependency advisories ─────────────────────────────────────────
  {
    id: 'CVE-2026-40100',
    title: 'ws (WebSocket) denial-of-service via crafted frame',
    agent: '*',
    affectedVersions: '>=0.0.0',
    severity: 'warning',
    description: 'The ws package before 8.17.1 is vulnerable to DoS via specially crafted WebSocket frames.',
    published: '2026-01-08',
    tags: ['dependency'],
    affectedDependency: { name: 'ws', versionConstraint: '>=0.0.0 <8.17.1' },
  },

  // ── MCP package advisories ────────────────────────────────────────
  // Matched by MCP-027 against pinned `npx pkg@version` server specs.
  // First published in advisory feed v2 (2026-07-10); folded into the
  // bundle so fresh installs get them without `vaso update`.
  {
    id: 'CVE-2025-6514',
    title: 'mcp-remote OS command injection via malicious MCP server (RCE)',
    agent: 'mcp',
    affectedVersions: '>=0.0.5 <0.1.16',
    fixedVersion: '0.1.16',
    severity: 'critical',
    description: 'A malicious or compromised remote MCP server can return a crafted authorization_endpoint URL during OAuth flow initialization; mcp-remote passes it to open(), resulting in arbitrary OS command execution on the connecting client (full parameter control on Windows via PowerShell subexpression evaluation; arbitrary executable launch on macOS/Linux). CVSS 9.6.',
    reference: 'https://github.com/advisories/GHSA-6xpm-ggf7-wc3p',
    published: '2025-07-09',
    exploitAvailable: true,
    tags: ['mcp', 'cve', 'rce'],
    affectedDependency: { name: 'mcp-remote', versionConstraint: '>=0.0.5 <0.1.16' },
  },
  {
    id: 'CVE-2025-49596',
    title: 'MCP Inspector proxy missing authentication enables browser-based RCE',
    agent: 'mcp',
    affectedVersions: '<0.14.1',
    fixedVersion: '0.14.1',
    severity: 'critical',
    description: 'The MCP Inspector proxy accepted unauthenticated requests to launch MCP commands over stdio; a malicious website visited by the developer could reach the locally-running proxy (CSRF / 0.0.0.0-day / DNS rebinding) and execute arbitrary code on the host. Fixed in 0.14.1 with a default proxy session token and allowed-origin verification. CVSS 9.4.',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2025-49596',
    published: '2025-06-13',
    exploitAvailable: true,
    tags: ['mcp', 'cve', 'rce'],
    affectedDependency: { name: '@modelcontextprotocol/inspector', versionConstraint: '<0.14.1' },
  },
  {
    id: 'CVE-2025-53109',
    title: 'Filesystem MCP server symlink bypass grants full filesystem access (EscapeRoute)',
    agent: 'mcp',
    affectedVersions: '>=0.2.0 <2025.7.1',
    fixedVersion: '2025.7.1',
    severity: 'critical',
    description: 'Symbolic-link checks in @modelcontextprotocol/server-filesystem fall back to parent-directory validation, so a symlink pointing outside the allowed roots grants read/write access to the entire filesystem, escalating to code execution via LaunchAgents/cron. No fixed 0.x release was published — upgrade to 2025.7.1 or later. CVSS 8.4.',
    reference: 'https://cymulate.com/blog/cve-2025-53109-53110-escaperoute-anthropic/',
    published: '2025-07-01',
    exploitAvailable: true,
    tags: ['mcp', 'cve', 'sandbox-escape'],
    affectedDependency: { name: '@modelcontextprotocol/server-filesystem', versionConstraint: '>=0.2.0 <2025.7.1' },
  },
  {
    id: 'CVE-2025-53110',
    title: 'Filesystem MCP server directory containment bypass via prefix match (EscapeRoute)',
    agent: 'mcp',
    affectedVersions: '>=0.2.0 <2025.7.1',
    fixedVersion: '2025.7.1',
    severity: 'warning',
    description: 'Path validation in @modelcontextprotocol/server-filesystem used a naive string-prefix check, so any path that merely starts with an allowed directory string (e.g. /tmp/allowed_dir-evil next to /tmp/allowed_dir) is treated as in scope, allowing listing, reading, and writing outside the configured sandbox. CVSS 7.3.',
    reference: 'https://cymulate.com/blog/cve-2025-53109-53110-escaperoute-anthropic/',
    published: '2025-07-01',
    tags: ['mcp', 'cve', 'sandbox-escape'],
    affectedDependency: { name: '@modelcontextprotocol/server-filesystem', versionConstraint: '>=0.2.0 <2025.7.1' },
  },
  {
    id: 'VASO-MAL-2025-001',
    title: 'postmark-mcp npm package backdoored — BCC exfiltration of all outgoing email',
    agent: 'mcp',
    affectedVersions: '>=1.0.16',
    severity: 'critical',
    description: "The postmark-mcp npm package impersonated Postmark Labs' MCP server; version 1.0.16 added a hidden BCC of every email sent through the server to an attacker address at giftshop.club (first confirmed malicious MCP server in the wild, Koi Security). The package was removed from npm; any remaining install at 1.0.16 or later is backdoored and should be removed, and mail credentials rotated. There is no fixed version — use the official Postmark-published server instead.",
    reference: 'https://www.koi.ai/blog/postmark-mcp-npm-malicious-backdoor-email-theft',
    published: '2025-09-26',
    tags: ['mcp', 'malicious-package', 'supply-chain'],
    affectedDependency: { name: 'postmark-mcp', versionConstraint: '>=1.0.16' },
  },

  // ── Config-pattern advisory ───────────────────────────────────────
  {
    id: 'VASO-CFG-2026-001',
    title: 'Dangerous auto_approve_tools wildcard pattern',
    agent: '*',
    affectedVersions: '>=0.0.0',
    severity: 'critical',
    description: 'Setting auto_approve_tools to "*" or "all" disables tool approval, allowing unrestricted tool execution.',
    published: '2025-12-01',
    tags: ['config'],
    configPattern: { key: 'auto_approve_tools', valuePattern: '^(\\*|all)$' },
  },
];

let _db: AdvisoryDatabase | null = null;
let _initialized = false;

export function buildBundledAdvisoryDatabase(): AdvisoryDatabase {
  return {
    advisories: [...BUNDLED_ADVISORIES],
  };
}

export async function initAdvisoryDatabase(): Promise<void> {
  if (_initialized) return;

  const bundled = buildBundledAdvisoryDatabase();

  try {
    const { loadCachedAdvisoryFeed, mergeAdvisoryFeed } = await import('./updater.js');
    const feedData = await loadCachedAdvisoryFeed();
    if (feedData) {
      _db = mergeAdvisoryFeed(bundled, feedData);
    } else {
      _db = bundled;
    }
  } catch {
    _db = bundled;
  }

  _initialized = true;
}

export function getAdvisoryDatabase(): AdvisoryDatabase {
  if (!_db) {
    _db = buildBundledAdvisoryDatabase();
  }
  return _db;
}

export function reloadAdvisoryDatabase(): void {
  _db = null;
  _initialized = false;
}
