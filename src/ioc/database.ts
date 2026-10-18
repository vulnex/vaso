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
  // MemTensor/sckit worm (Sep 2026): trojanized OpenClaw memory plugin
  // @memtensor/memos-cloud-openclaw-plugin + PyPI MemoryOS (Aikido;
  // StepSecurity lists it as a historical resolution of the C2).
  '139.84.223.178',
  // Carbonato botnet (Sep 2026): Hermes Agent run on hijacked Docker hosts
  // (ThreatDown).
  '45.79.183.61',
  '91.99.195.164',
  '213.136.79.115',
  '213.136.83.197',
  '190.211.124.187',
  // Malicious ClawHub skills that passed screening (Unit 42, Jun 2026).
  '2.26.75.16',
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
  // postmark-mcp backdoor exfiltration domain (Koi Security, Sep 2025;
  // VASO-MAL-2025-001).
  'giftshop.club',
  // MemTensor/sckit worm C2, all subdomains (StepSecurity/SafeDep/Aikido, Sep 2026).
  'skyleen.fr',
  // Deadbugz malicious "productivity-suite" MCP server (Pillar Security, Aug 2026).
  'productivity-suite-mcp.onrender.com',
  // ChainDrop / keyv npm worm that plants .claude/settings.json SessionStart
  // hooks (Datadog Security Labs, Aikido, Socket; Aug 2026).
  'npm-cache.com',
  'js-mirror.com',
  'pypi-get.com',
  'awqhnjewqjkl.icu',
  // Carbonato Hermes-Agent botnet proxies (ThreatDown, Sep 2026).
  'carbonato-proxy-drab.vercel.app',
  'carbonato-proxy-zeta.vercel.app',
  'carbonato-proxy-zeta-2.vercel.app',
  // Malicious ClawHub skill payload hosts (Unit 42, Jun 2026).
  'install.app-distribution.net',
  'laosji.net',                  // money-radar affiliate payload host
  'openclawcli.vercel.app',
  // Fake Claude/Codex installer pages delivering a ClickFix in-memory stealer
  // (Intellibron, Jun 2026).
  'primemetricsa.com',
  'claudescript.top',
  'creativecommunityinfo.art',
  'code.codixcody.com',
  'mycodingtoolsd.com',
  'codex-promo.com',
  'cladehub.com',
  'cladesktop-apps.com',
  'too.clawddddd.com',
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
  // MemTensor/sckit worm (Sep 2026): sckit Go stealer dropped by the trojanized
  // OpenClaw memory plugin (npm) and PyPI MemoryOS (StepSecurity/SafeDep/Aikido).
  '381ac6dc1715d9298fe81b2a53a11f7b7d78e361ee3a6619ad54f8c4b062cc18', // sckit linux-amd64 (npm)
  'e077c387b223811064b7bbc5a55a0182fca9bf50894f949ff284d4be87d44b26', // sckit linux-arm64 (npm)
  '65faf8ccbcf5b34eb4f72c71bf82815fa9c1e2f947b9c898491540e866132c31', // sckit darwin-amd64 (npm)
  'f8ccdd1da7dff1aef16377a2842bc7acf7c516e32122dd6e42dc4a4e57653fce', // sckit darwin-arm64 (npm)
  '56cd3416d2ec2aa7e7cec2a06010cf0b58eb09c0a5486809df52afeaca8f14be', // sckit windows-amd64 (npm)
  'd6b3e77c36ee8017c9bf30d1da7218ec0ea843768d313eb8e35845c8a9b38a26', // sckit windows-arm64 (npm)
  '9de0d5b0ca184f71f630be5781d134998883a02d5d7bc65aeb9559d8f9efb364', // sckit darwin-amd64 (PyPI)
  '5405e330507602e803f7dd6f2a9d4555aec8558ab222b51413594a962da6888a', // sckit darwin-arm64 (PyPI)
  'c1b0998347b489582bae7b7f4930f9831d9ef4b6bc150cfd488ee1a43272dd36', // sckit linux-amd64 (PyPI)
  '8f647f17a1934679c4095e21bee2b9bd83e28476603758bc91408a0c8443e3b4', // sckit linux-arm64 (PyPI)
  '16de381deb978744535b10f68fe15165251374b86eef18ffc2c47f61ea673047', // sckit windows-amd64 (PyPI)
  'f7c4014e284f3d56c452b8b222a287c54f73dc4a40a7e022e765ac8376362947', // sckit windows-arm64 (PyPI)
  // ChainDrop / keyv npm worm (Aug 2026; Datadog Security Labs, Aikido, Socket).
  '14eb4ce01dd4307759887ff819359b70d7d9ff709ecde039a5abc1aac325b128', // injected .claude/settings.json (SessionStart hook)
  '927387d0cfac1118df4b383decc2ea6ba49c9d2f98b47098bcbcba1efc026e1f', // injected .vscode/tasks.json
  'fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb', // setup.mjs loader (.claude/.vscode copy)
  '54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668', // setup.mjs npm preinstall loader
  '9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc', // Math_Symbol.js / math_init.js payload
  // @7nohe/openapi-react-query-codegen compromise (Socket, Aug 2026): tampers
  // with AI-tool rules files and mcp.json.
  'b49afb7dba04cd99b357ce7c652c823a3707f28e130bd5c6645851a7adc030d6', // 3FWCvzduYZg.js config tamperer
  '59370c67b54a0ccaedd265e2356f04540b2fba1e1845300ef6de4d5437d99380', // 3FWCvzduYZg.js variant
  'd3246926b20a8d021ed7de0ac8e9eee1dda986088f84ba18f31cb2042a121f5d', // binding.gyp
  // Malicious ClawHub skills that passed screening (Unit 42, Jun 2026).
  '818aea6143282b352fdfdc0f3ebf77a36e54eb3befb5cad1a355a99ab97c6aa7', // cluw macOS infostealer
  '881ce5cb124c4d2e814783724cc1388f6a1cbf6eee274c3f3366e77ba3503ad7', // listed by Unit 42 without description
  'b30eaed1f7478c28f4ec50d07ed5ef014ffbc4b2bc5a38d689ba9f7abb5e19c2', // omnicogg skill (AMOS dropper)
  'b6c7e0bf573b1c7d9d3a05eb08d26579199515b847df984862805f44a7af8007', // TradingView assistant skill
  'ebb73dbb5aac1f6fe1a88e8f26126a1e1aa34c9f3345ad4345189b40d9bf1d1d', // money-radar skill
  'f4e41aa269c88bf11a2022701a9cf41e9a186aa1b224d837c31bf34e0b875d0e', // letssendit skill
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
  /\bhack(?:ing)?[-_ ]?tools?\b/i,
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
  // Verified-good ClawHub skill names from the Agent Threat Rules public
  // whitelist (github.com/Agent-Threat-Rule/agent-threat-rules, MIT,
  // 2026-04-16) — the IOC-005 lookalike reference, alongside the names above.
  'ai-code-assistant',
  'ai-content-rewriter',
  'ai-data-visualization',
  'ai-writing-agent',
  'audio-editor',
  'botlearn-writer',
  'catalan',
  'daily-motivation',
  'daily-reminder',
  'dutch',
  'email-draft-oc',
  'english',
  'estonian',
  'healthy-eating',
  'hebrew',
  'hindi',
  'hungarian',
  'irish',
  'is-token-safe',
  'italian',
  'kindergarten-assistant',
  'latvian',
  'lithuanian',
  'market-news',
  'memo-teller',
  'moments-grid',
  'narrative-voice',
  'oc-full-ops-audit-recipe',
  'official-layout-pro',
  'philosophy',
  'polish',
  'portuguese',
  'quant-strategy',
  'slovak',
  'spanish',
  'strategic-analyst',
  'transmissions',
  'vietnamese',
  'virtually-us',
  'writing-reboot-review',
];

const BINARY_PATTERNS: BinaryPattern[] = [
  { name: 'ELF binary', pattern: Buffer.from([0x7f, 0x45, 0x4c, 0x46]), type: 'buffer' },
  { name: 'Mach-O 64-bit binary', pattern: Buffer.from([0xcf, 0xfa, 0xed, 0xfe]), type: 'buffer' },
  { name: 'Mach-O 32-bit binary', pattern: Buffer.from([0xce, 0xfa, 0xed, 0xfe]), type: 'buffer' },
  { name: 'PE/DOS executable', pattern: Buffer.from([0x4d, 0x5a]), type: 'buffer' },
  { name: 'NUL-padding shellcode', pattern: /\x00{16,}/, type: 'regex' },
  { name: 'Packed JS eval wrapper', pattern: /eval\(function\(p,a,c,k,e/, type: 'regex' },
];

// Every name here resolves on its registry (checked 2026-10-11): an entry that
// doesn't exist is worse than none — an exact match is exempt from the
// typosquat test, so an unclaimed "trusted" name is free for an attacker to
// register. npm unless marked (PyPI).
const TRUSTED_MCP_PACKAGES = [
  // Model Context Protocol reference servers (npm; several now archived upstream).
  '@modelcontextprotocol/server-filesystem',
  '@modelcontextprotocol/server-github',
  '@modelcontextprotocol/server-gitlab',
  '@modelcontextprotocol/server-google-maps',
  '@modelcontextprotocol/server-memory',
  '@modelcontextprotocol/server-postgres',
  '@modelcontextprotocol/server-puppeteer',
  '@modelcontextprotocol/server-sequential-thinking',
  '@modelcontextprotocol/server-slack',
  '@modelcontextprotocol/server-brave-search',
  '@modelcontextprotocol/server-everything',
  '@modelcontextprotocol/server-redis',
  '@modelcontextprotocol/server-gdrive',
  '@modelcontextprotocol/server-aws-kb-retrieval',
  '@modelcontextprotocol/server-everart',
  // Reference servers published to PyPI (run with uvx).
  'mcp-server-fetch',
  'mcp-server-sqlite',
  'mcp-server-git',
  'mcp-server-time',
  // Vendor and widely used community servers (npm).
  '@playwright/mcp',
  '@upstash/context7-mcp',
  '@notionhq/notion-mcp-server',
  '@sentry/mcp-server',
  '@stripe/mcp',
  '@supabase/mcp-server-supabase',
  '@cloudflare/mcp-server-cloudflare',
  '@heroku/mcp-server',
  '@hubspot/mcp-server',
  '@azure/mcp',
  '@browsermcp/mcp',
  '@21st-dev/magic',
  '@agentdeskai/browser-tools-mcp',
  'firecrawl-mcp',
  'tavily-mcp',
  'exa-mcp-server',
  'mongodb-mcp-server',
  'figma-developer-mcp',
  'mcp-server-kubernetes',
  'task-master-ai',
  'mcp-remote',
  'supergateway',
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
