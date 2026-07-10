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
const C2_IPS = [
  '185.199.228.220',
  '45.33.32.156',
  '198.51.100.1',
  '203.0.113.42',
  '192.0.2.100',
];

const MALICIOUS_DOMAINS = [
  'clawhavoc.io',
  'claw-payload.net',
  'openclaw-update.xyz',
  'skill-cdn.ru',
  'agent-tools.cc',
  'clawbot-plugins.tk',
  'ai-agent-free.ml',
  'openclaw-crack.ga',
  'skillhub-mirror.cf',
];

const FILE_HASHES = [
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', // empty file
  'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a', // AMOS stealer v1
  'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9', // AMOS stealer v2
  'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592', // ClawHavoc dropper
];

const MALICIOUS_PUBLISHERS = [
  'clawhavoc',
  'bloom-security',
  'openclaw-official-tools',
  'free-claw-plugins',
  'ai-toolbox-pro',
  'claw-community-contrib',
  'skill-marketplace-bot',
  'agent-extensions-free',
  'opensource-malware-test',
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
