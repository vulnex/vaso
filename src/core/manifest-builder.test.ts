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
    ];
    expect(manifest.metadataGlobPatterns).toEqual(expect.arrayContaining(stores));
    const content = [...manifest.globPatterns, ...manifest.filePaths];
    for (const p of stores) expect(content).not.toContain(p);
  });

  it('runs agent CLIs with an isolated HOME, system tools with the real one', () => {
    const byId = new Map(manifest.commands.map(c => [c.id, c]));
    for (const id of ['hermes-version', 'cursor-agent-version', 'gemini-version', 'copilot-version', 'nemoclaw-pip3-show', 'abacusai-version']) {
      expect(byId.get(id)?.isolateHome, id).toBe(true);
    }
    for (const id of ['claude-which', 'ps-ancestry', 'crontab-list', 'chatgpt-plist-main', 'claude-desktop-version']) {
      expect(byId.get(id)?.isolateHome, id).toBeUndefined();
    }
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
    ]));
    // Never also collected with content
    const content = [...manifest.globPatterns, ...manifest.filePaths];
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
});
