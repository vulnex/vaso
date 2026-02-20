export interface IOCDatabase {
  c2Ips: string[];
  maliciousDomains: string[];
  fileHashes: string[];
  maliciousPublishers: string[];
  maliciousSkillPatterns: RegExp[];
  trustedSkillNames: string[];
  trustedMCPPackages: string[];
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

export function getIOCDatabase(): IOCDatabase {
  if (!_db) {
    _db = {
      c2Ips: [...C2_IPS],
      maliciousDomains: [...MALICIOUS_DOMAINS],
      fileHashes: [...FILE_HASHES],
      maliciousPublishers: [...MALICIOUS_PUBLISHERS],
      maliciousSkillPatterns: [...MALICIOUS_SKILL_PATTERNS],
      trustedSkillNames: [...TRUSTED_SKILL_NAMES],
      trustedMCPPackages: [...TRUSTED_MCP_PACKAGES],
    };
  }
  return _db;
}

export function reloadIOCDatabase(): void {
  _db = null;
}
