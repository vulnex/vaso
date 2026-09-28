import { describe, it, expect } from 'vitest';
import type { AgentAdapter } from '../adapters/adapter.js';
import { buildProbeManifest } from './manifest-builder.js';
import { allAdapters } from '../adapters/index.js';

describe('buildProbeManifest', () => {
  const manifest = buildProbeManifest(allAdapters as AgentAdapter[]);

  it('keeps private session/conversation stores metadata-only', () => {
    expect(manifest.metadataGlobPatterns).toEqual(expect.arrayContaining([
      '~/.codex/sessions/*/*/*/rollout-*.jsonl',
      '~/Library/Application Support/com.openai.chat/conversations-v3-*/**',
      '~/.gemini/tmp/*/chats/session-*.jsonl',
      '~/.copilot/command-history-state.json',
      '~/.copilot/session-state/*',
      '~/Library/Application Support/com.meta.endo/**',
    ]));
    // Never also collected with content
    const content = [...manifest.globPatterns, ...manifest.filePaths];
    for (const p of ['~/.gemini/tmp/*/chats/session-*.jsonl', '~/.copilot/command-history-state.json',
      '~/.copilot/session-state/*.json', '~/Library/Application Support/com.meta.endo/**']) {
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
