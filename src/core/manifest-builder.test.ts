import { describe, it, expect } from 'vitest';
import type { AgentAdapter } from '../adapters/adapter.js';
import { buildProbeManifest } from './manifest-builder.js';
import { allAdapters } from '../adapters/index.js';

describe('buildProbeManifest', () => {
  const manifest = buildProbeManifest(allAdapters as AgentAdapter[]);

  it('ships credential token stores with permissions only (checks never read them)', () => {
    const stores = [
      '~/.claude/.credentials.json',
      '~/.local/share/devin/credentials.toml',
      '~/.gemini/oauth_creds.json', '~/.gemini/google_accounts.json', '~/.gemini/mcp-oauth-tokens.json',
      '~/.qwen/oauth_creds.json', '~/.qwen/mcp-oauth-tokens.json', '~/.qwen/google_accounts.json',
      '~/.abacusai/keystore.enc*',
      // OAuth / provider tokens no check reads (found in a remote snapshot, 2026-10-11)
      '~/.codex/auth.json',
      '~/.local/share/opencode/auth.json',
      '~/.hermes/credentials.json', '~/.hermes/auth.json', '~/.hermes/mcp-tokens/*.json',
      '~/.openclaw/credentials.json', '~/.openclaw/auth.json',
    ];
    expect(manifest.metadataGlobPatterns).toEqual(expect.arrayContaining(stores));
    const content = [...manifest.globPatterns, ...manifest.filePaths];
    for (const p of stores) expect(content).not.toContain(p);
  });

  it("asks for POL-005's credential files as metadata only, two levels deep", () => {
    const cred = manifest.metadataGlobPatterns!.filter(g => g.includes('.netrc'));
    expect(cred).toEqual(expect.arrayContaining([
      '~/.openclaw/{.npmrc,.netrc,.pgpass,.my.cnf,.s3cfg,credentials,secrets.txt,.boto,.pypirc,.authinfo}',
      '~/.openclaw/*/*/{.npmrc,.netrc,.pgpass,.my.cnf,.s3cfg,credentials,secrets.txt,.boto,.pypirc,.authinfo}',
    ]));
    expect([...manifest.globPatterns, ...manifest.filePaths].filter(g => g.includes('.netrc'))).toEqual([]);
  });

  it("ships the installed copies of advisory-named dependencies next to an install's package.json", () => {
    expect(manifest.globPatterns.some(g => g.startsWith('~/.openclaw/node_modules/{') && g.includes('postmark-mcp'))).toBe(true);
    expect(manifest.globPatterns).toContain('~/.openclaw/package-lock.json');
  });

  it('runs agent CLIs with an isolated HOME, system tools with the real one', () => {
    const byId = new Map(manifest.commands.map(c => [c.id, c]));
    for (const id of ['hermes-version-flag', 'cursor-agent-version', 'gemini-version', 'copilot-version', 'nemoclaw-pip3-show', 'abacusai-version']) {
      expect(byId.get(id)?.isolateHome, id).toBe(true);
    }
    for (const id of ['claude-which', 'ps-ancestry', 'crontab-list', 'chatgpt-plist-main', 'claude-desktop-version']) {
      expect(byId.get(id)?.isolateHome, id).toBeUndefined();
    }
  });

  it('runs OpenShell gateway queries with the real HOME, expanding per sandbox', () => {
    const byId = new Map(manifest.commands.map(c => [c.id, c]));
    expect(byId.get('openshell-version')?.isolateHome).toBe(true);
    for (const id of ['openshell-sandbox-list', 'openshell-sandbox-policy', 'openshell-global-policy']) {
      expect(byId.get(id)?.isolateHome, id).toBe(false);
    }
    expect(byId.get('openshell-sandbox-policy')?.forEach).toEqual({ from: 'openshell-sandbox-list', array: 'sandboxes', fields: ['name', 'workspace'], defaults: { workspace: 'default' } });
    // The only real-HOME agent commands: read-only queries verified side-effect free
    const realHomeAgentCmds = manifest.commands.filter(c => c.isolateHome === false).map(c => c.id);
    expect(realHomeAgentCmds.sort()).toEqual(['openshell-global-policy', 'openshell-sandbox-list', 'openshell-sandbox-policy']);
  });

  it('keeps OpenShell keys, tokens and the credential database metadata-only', () => {
    expect(manifest.metadataGlobPatterns).toEqual(expect.arrayContaining([
      '~/.config/openshell/gateways/*/mtls/*',
      '~/.config/openshell/gateways/*/oidc_token.json',
      '~/.local/state/openshell/gateway/openshell.db*',
      '~/.local/state/openshell/gateway/credentials/*',
      '~/.local/state/openshell/docker-sandbox-tokens/**',
      '/opt/homebrew/var/openshell/tls/ca.key',
    ]));
    const content = [...manifest.globPatterns, ...manifest.filePaths];
    expect(content.filter(p => /openshell.*(?:mtls|\.key|signing|credentials|tokens|\.db)/.test(p))).toEqual([]);
  });

  it('adds a ${VAR} twin for every path under an env-relocatable tree', () => {
    expect(manifest.filePaths).toEqual(expect.arrayContaining([
      '~/.picoclaw/config.json', '${PICOCLAW_HOME}/config.json', '${PICOCLAW_CONFIG}',
      '${CODEX_HOME}/config.toml', '${CLAUDE_CONFIG_DIR}/settings.json', '${CLAUDE_CONFIG_DIR}/.claude.json',
      '${OPENSHELL_SANDBOX_POLICY}',
    ]));
    expect(manifest.globPatterns).toEqual(expect.arrayContaining(['${HERMES_HOME}/skills/**']));
    expect(manifest.directoryListings).toEqual(expect.arrayContaining(['${XDG_CONFIG_HOME}/opencode']));
    // privacy holds for twins: a metadata-only path's twin is metadata-only too
    expect(manifest.metadataGlobPatterns).toEqual(expect.arrayContaining(['${OPENCLAW_HOME}/.openclaw/memory.json', '${OPENCLAW_STATE_DIR}/memory.json']));
    expect([...manifest.filePaths, ...manifest.globPatterns]).not.toContain('${OPENCLAW_HOME}/.openclaw/memory.json');
    expect([...manifest.filePaths, ...manifest.globPatterns]).not.toContain('${OPENCLAW_STATE_DIR}/memory.json');
  });

  it('collects a Grok Bot install moved with SAND_DATA_ROOT / SAND_USER_DATA_DIR (dt15 B1)', () => {
    expect(manifest.filePaths).toEqual(expect.arrayContaining([
      '${SAND_DATA_ROOT}/settings.json', '${SAND_USER_DATA_DIR}/sand-data/settings.json',
      '${SAND_USER_DATA_DIR}/desktop-status.json',
    ]));
    expect(manifest.directoryListings).toEqual(expect.arrayContaining(['${SAND_DATA_ROOT}', '${SAND_USER_DATA_DIR}']));
    // Secret stores and contact lists stay metadata-only under the relocation too
    const secrets = ['${SAND_DATA_ROOT}/local-exec-daemon-credential.json', '${SAND_DATA_ROOT}/local-tool-standing-grants.v1.json',
      '${SAND_USER_DATA_DIR}/sand-secrets.json', '${SAND_USER_DATA_DIR}/user-secrets.json'];
    expect(manifest.metadataGlobPatterns).toEqual(expect.arrayContaining(secrets));
    for (const p of secrets) expect([...manifest.filePaths, ...manifest.globPatterns]).not.toContain(p);
  });

  it('keeps private session/conversation stores metadata-only', () => {
    expect(manifest.metadataGlobPatterns).toEqual(expect.arrayContaining([
      '~/.codex/sessions/*/*/*/rollout-*.jsonl',
      '~/Library/Application Support/com.openai.chat/conversations-v3-*/**',
      '~/.gemini/tmp/*/chats/session-*.jsonl',
      '~/.copilot/command-history-state.json',
      '~/.copilot/session-state/*',
      '~/Library/Application Support/com.meta.endo/**',
      '~/.abacusai/history.jsonl',
      '~/.abacusai/projects/**',
      '~/.openclaw/memory.json',
      '~/.openclaw/conversations.db',
      '~/Library/Application Support/Claude/Local Storage/leveldb/*.ldb',
      '~/Library/Application Support/Claude/Local Storage/leveldb/*.log',
    ]));
    // Never also collected with content
    const content = [...manifest.globPatterns, ...manifest.filePaths];
    expect(content.filter(p => /conversation|Local Storage|\/memory\.json$/.test(p))).toEqual([]);
    for (const p of ['~/.gemini/tmp/*/chats/session-*.jsonl', '~/.copilot/command-history-state.json',
      '~/.copilot/session-state/*.json', '~/Library/Application Support/com.meta.endo/**',
      '~/.abacusai/history.jsonl', '~/.abacusai/projects/**']) {
      expect(content).not.toContain(p);
    }
    for (const g of manifest.metadataGlobPatterns ?? []) expect(manifest.globPatterns).not.toContain(g);
  });

  it('collects what remote-only gaps needed (RUN-001 units, CDX-010 rules, Linux Windsurf roots, hermes --version)', () => {
    expect(manifest.directoryListings).toContain('~/.config/systemd/user');
    expect(manifest.systemDirListings).toContain('/etc/systemd/system');
    expect(manifest.globPatterns).toEqual(expect.arrayContaining(['~/.config/systemd/user/*.service*', '~/.codex/rules/*.rules']));
    expect(manifest.filePaths).toContain('~/devin-desktop/resources/app/product.json');
    expect(manifest.commands.some(c => c.cmd === 'hermes' && c.args.join(' ') === '--version')).toBe(true);
  });

  it('inventories every CLI copy (system prefixes, user bins, each nvm Node) as metadata only', () => {
    const everywhere = [...manifest.metadataGlobPatterns!, ...manifest.globPatterns, ...manifest.filePaths];
    for (const cli of ['codex', 'openclaw', 'atomic-agent', 'devin']) {
      expect(everywhere).toContain(`~/.nvm/versions/node/*/bin/${cli}`);
      expect(everywhere).toContain(`~/.local/bin/${cli}`);
    }
    expect([...manifest.metadataGlobPatterns!, ...manifest.systemPaths!]).toEqual(expect.arrayContaining(['/usr/bin/codex', '/opt/homebrew/bin/claude', '/usr/bin/openclaw']));
  });

  // Remote scans see only what the manifest collects: a skills dir it misses
  // makes every SKL/IOC check pass vacuously on --host / --snapshot scans.
  it('collects every skills dir an adapter reports, so remote skill checks have code to read', () => {
    for (const adapter of allAdapters as AgentAdapter[]) {
      const dir = adapter.getSkillsDir?.('/x');
      if (!dir) continue;
      const globs = adapter.getProbeManifest?.().globPatterns ?? [];
      // getSkillsDir(installDir) → '<installDir>/<suffix>'; some ignore installDir
      const suffix = dir.startsWith('/x/') ? dir.slice(3) : dir.split('/').slice(-2).join('/');
      expect(globs.some(g => g.endsWith(`/${suffix}/**`)), `${adapter.agent}: no '…/${suffix}/**' glob`).toBe(true);
    }
  });

  it('collects user-scope skill roots beyond getSkillsDir (shared ~/.agents, legacy dirs, open-skills)', () => {
    const byAgent = new Map((allAdapters as AgentAdapter[]).map(a => [a.agent, a.getProbeManifest?.().globPatterns ?? []]));
    const expected: Record<string, string[]> = {
      'cursor-cli': ['~/.cursor/skills-cursor/**'],
      abacus: ['~/.abacusai/skills/**', '~/.agents/skills/**'],
      devin: ['~/.config/devin/skills/**', '~/.config/cognition/skills/**', '~/.agents/skills/**'],
      windsurf: ['~/.codeium/windsurf/skills/**', '~/.config/devin/skills/**', '~/.agents/skills/**'],
      openclaw: ['~/.openclaw/skills/**', '~/.clawdbot/skills/**', '~/.moltbot/skills/**', '/etc/openclaw/skills/**'],
      zeroclaw: ['~/.zeroclaw/shared/skills/**', '~/open-skills/**', '/opt/homebrew/var/zeroclaw/shared/skills/**'],
    };
    for (const [agent, globs] of Object.entries(expected)) {
      expect(byAgent.get(agent as AgentAdapter['agent']), agent).toEqual(expect.arrayContaining(globs));
    }
  });

  it('never runs `hermes version` (installs dependencies in a fresh data root)', () => {
    const hermes = manifest.commands.filter((c) => c.cmd === 'hermes');
    expect(hermes.map((c) => c.args)).toEqual([['--version']]);
  });
});
