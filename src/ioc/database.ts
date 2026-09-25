export interface BinaryPattern {
  name: string;
  pattern: Buffer | RegExp;
  type: 'buffer' | 'regex';
}

export interface IOCDatabase {
  c2Ips: string[];
  maliciousDomains: string[];
  fileHashes: string[];
  maliciousPublishers: string[];
  maliciousSkillPatterns: RegExp[];
  trustedSkillNames: string[];
  trustedMCPPackages: string[];
  binaryPatterns: BinaryPattern[];
}

// Ported from openclaw-security-monitor IOC data
// Never add documentation/test values here: RFC 5737 ranges (192.0.2/24,
// 198.51.100/24, 203.0.113/24) and scanme.nmap.org (45.33.32.156) shipped as
// "C2" in v0.1.0 and matched benign content (e.g. Google API discovery docs).
// Guarded by src/ioc/database.test.ts.
const C2_IPS = [
  // ClawHavoc (Jan 2026): the AMOS stealer C2 shared by all 335 AMOS-delivering
  // ClawHub skills (Koi Security; The Hacker News 2026-02; OWASP Agentic
  // Skills Top 10 case studies; Unit 42).
  '91.92.242.30',
];

const MALICIOUS_DOMAINS = [
  // C2/relay domains of malicious npm packages that remote-control AI coding
  // agents (drive claude/codex/gemini with --dangerously-skip-permissions over
  // a WebSocket/relay channel). Confirmed via OSV MAL records (amazon-inspector
  // source), Aug 2026 campaign. osv.dev/vulnerability/MAL-2026-<id>.
  'agenthub.contetial.com',      // MAL-2026-13399 (agenthub-multiagent-mcp)
  'hub.client-llm.com',          // MAL-2026-13209 (@guangnao/claude-cli)
  'relay.mangomindbd.com',       // MAL-2026-13611 (mangomind-agent)
  'remote-claude-relay.fly.dev', // MAL-2026-13455 (remote-claude-daemon; attacker-controlled app subdomain)
  'santaclaude.app',             // MAL-2026-13363 (@cliphijack/santaclaude)
  'agenthub-agent.fyenet.com',   // MAL-2026-13615 (agenthub-ai)
  'claude.pishchykau.eu',        // MAL-2026-13376 (claude-remote-agent)
  'canvas.xiaohhhh1.com',        // MAL-2026-13398 (@xiaohhhh1/canvas-agent)
  'newsradar.dreamdt.cn',        // MAL-2026-3757 (claw-subagent-service, May 2026)
  // C2 domains of the July-2025 malicious "Solidity Language" Open VSX
  // extensions targeting Cursor IDE (ScreenConnect → Quasar RAT; ~$500K crypto
  // theft; Kaspersky/Securelist).
  'angelic.su',
  'relay.lmfao.su',
];

// Real, sourced SHA-256 hashes only. v0.1.0 shipped textbook test vectors
// here (empty file, "hello world", "quick brown fox", SHA3-256 of "") labelled
// as malware, flagging every empty __init__.py as critical. Guarded by
// src/ioc/database.test.ts.
const FILE_HASHES = [
  // GHAPPIER supply-chain attack (@dforge-core/dforge-mcp 0.2.20/0.2.21,
  // npm trusted-publishing abuse, 2026-09-09; CloudSEK research).
  'e9045b27557e5019fe44a1d5ae4b77714faa65fef883127ca7db85b7970afab4', // GHAPPIER carrier tarball 0.2.21
  'f2c8234c00b1f5b0b135534bf51207dc0239647890b73531996d60c90cf9e866', // GHAPPIER skills/indexe.cjs
  'c8337c06f4d3e79dd65aca4058b7a32c763468cdc7df76a849c55395d703a40d', // GHAPPIER stage-1 dispatcher
];

const MALICIOUS_PUBLISHERS = [
  // Confirmed-malware OpenClaw skill publishers, sourced from the Agent Threat
  // Rules public blacklist (github.com/Agent-Threat-Rule/agent-threat-rules,
  // data/public-blacklist.json, 2026-04-16; MIT-licensed). These three named
  // threat actors account for all 552 confirmed-malware skills in that dataset
  // (hightower6eu: 354, sakaen736jih: 198); matching on publisher via IOC-004
  // flags every skill they ship, not just individually enumerated names.
  'hightower6eu',
  'sakaen736jih',
  '52yuanchangxing',
];

const MALICIOUS_SKILL_PATTERNS = [
  /claw.*havoc/i,
  /openclaw.*crack/i,
  /free.*premium/i,
  /hack.*tool/i,
  /stealer/i,
  /keylog/i,
  /rat[-_]?tool/i,
  /backdoor/i,
  /trojan/i,
  /miner[-_]?skill/i,
];

const TRUSTED_SKILL_NAMES = [
  'filesystem',
  'web-search',
  'calculator',
  'calendar',
  'weather',
  'translator',
  'code-runner',
  'database-query',
  'email-sender',
  'slack-bot',
  'github-helper',
  'docker-manager',
  'kubernetes-admin',
  'aws-cli',
  'gcp-tools',
  'azure-helper',
  'openai-chat',
  'image-generator',
  'pdf-reader',
  'markdown-editor',
];

const BINARY_PATTERNS: BinaryPattern[] = [
  { name: 'ELF binary', pattern: Buffer.from([0x7f, 0x45, 0x4c, 0x46]), type: 'buffer' },
  { name: 'Mach-O 64-bit binary', pattern: Buffer.from([0xcf, 0xfa, 0xed, 0xfe]), type: 'buffer' },
  { name: 'Mach-O 32-bit binary', pattern: Buffer.from([0xce, 0xfa, 0xed, 0xfe]), type: 'buffer' },
  { name: 'PE/DOS executable', pattern: Buffer.from([0x4d, 0x5a]), type: 'buffer' },
  { name: 'NUL-padding shellcode', pattern: /\x00{16,}/, type: 'regex' },
  { name: 'Packed JS eval wrapper', pattern: /eval\(function\(p,a,c,k,e/, type: 'regex' },
];

const TRUSTED_MCP_PACKAGES = [
  '@modelcontextprotocol/server-filesystem',
  '@modelcontextprotocol/server-github',
  '@modelcontextprotocol/server-gitlab',
  '@modelcontextprotocol/server-google-maps',
  '@modelcontextprotocol/server-memory',
  '@modelcontextprotocol/server-postgres',
  '@modelcontextprotocol/server-puppeteer',
  '@modelcontextprotocol/server-sequentialthinker',
  '@modelcontextprotocol/server-slack',
  '@modelcontextprotocol/server-sqlite',
  '@modelcontextprotocol/server-brave-search',
  '@modelcontextprotocol/server-fetch',
  '@modelcontextprotocol/server-everything',
  'mcp-server-fetch',
  'mcp-server-sqlite',
  'mcp-server-filesystem',
];

let _db: IOCDatabase | null = null;
let _initialized = false;

export function buildBundledDatabase(): IOCDatabase {
  return {
    c2Ips: [...C2_IPS],
    maliciousDomains: [...MALICIOUS_DOMAINS],
    fileHashes: [...FILE_HASHES],
    maliciousPublishers: [...MALICIOUS_PUBLISHERS],
    maliciousSkillPatterns: [...MALICIOUS_SKILL_PATTERNS],
    trustedSkillNames: [...TRUSTED_SKILL_NAMES],
    trustedMCPPackages: [...TRUSTED_MCP_PACKAGES],
    binaryPatterns: [...BINARY_PATTERNS],
  };
}

/**
 * Initialize the IOC database by loading any cached feed and merging
 * with bundled data. Call once at startup. Safe to call multiple times
 * (idempotent after first call unless reloadIOCDatabase() is called).
 */
export async function initIOCDatabase(): Promise<void> {
  if (_initialized) return;

  const bundled = buildBundledDatabase();

  try {
    const { loadCachedFeed, mergeFeedIntoDatabase } = await import('./updater.js');
    const feedData = await loadCachedFeed();
    if (feedData) {
      _db = mergeFeedIntoDatabase(bundled, feedData);
    } else {
      _db = bundled;
    }
  } catch {
    _db = bundled;
  }

  _initialized = true;
}

export function getIOCDatabase(): IOCDatabase {
  if (!_db) {
    _db = buildBundledDatabase();
  }
  return _db;
}

export function reloadIOCDatabase(): void {
  _db = null;
  _initialized = false;
}
