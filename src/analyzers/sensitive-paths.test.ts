import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { CREDENTIAL_STORE_SINKS, SENSITIVE_SINKS, classifySensitivePath, credentialStoreOf, isCredentialPath } from './sensitive-paths.js';

describe('SENSITIVE_SINKS', () => {
  it('is the list the probe enforces (probe/sensitive_sinks.go), pattern for pattern', () => {
    // The probe never ships content behind a skill link into one of these
    // locations, and the local skill walk never follows one: the two lists
    // must not drift (TestSensitiveSinksMatchTS checks the other direction).
    const go = readFileSync(join(__dirname, '..', '..', 'probe', 'sensitive_sinks.go'), 'utf-8');
    const block = /var sensitiveSinkPatterns = \[\]string\{([\s\S]*?)\n\}/.exec(go);
    expect(block).not.toBeNull();
    const probe = [...block![1].matchAll(/`([^`]*)`/g)].map(m => m[1]);
    expect(probe).toEqual(SENSITIVE_SINKS.map(s => s.re.source));
    // The probe compiles each one with (?i)
    expect(SENSITIVE_SINKS.every(s => s.re.flags === 'iu')).toBe(true);
  });

  it('names the same credential-store folders as the probe (credentialStoreSinks)', () => {
    const go = readFileSync(join(__dirname, '..', '..', 'probe', 'sensitive_sinks.go'), 'utf-8');
    const list = /var credentialStoreSinks = \[\]int\{([^}]*)\}/.exec(go);
    expect(list).not.toBeNull();
    expect(list![1].split(',').map(s => Number(s.trim()))).toEqual([...CREDENTIAL_STORE_SINKS]);
  });

  it('credentialStoreOf: folders of other tools\' credentials, as written — not agents\' own token files, /etc or shell startup files', () => {
    for (const p of ['/home/u/.aws/cop/config.json', '/home/u/.ssh/codex/config.toml', '/home/u/.AWS/x', '/home/u/.config/gh/cop/settings.json',
      '/home/u/.gnupg/a', '/home/u/.kube/a', '/home/u/.docker/a', '/Users/u/Library/Keychains/x', '/home/u/.mozilla/x']) {
      expect(credentialStoreOf(p), p).toBeDefined();
    }
    for (const p of ['/home/u/.copilot/config.json', '/etc/hermes/config.yaml', '/home/u/.bashrc', '/home/u/.codex/auth.json',
      '/home/u/.hermes/auth.json', '/home/u/.netrc', '/home/u/awsome/x']) {
      expect(credentialStoreOf(p), p).toBeUndefined();
    }
    expect(credentialStoreOf('/home/u/.aws/cop/config.json')).toBe('AWS credentials (~/.aws)');
  });

  it('classifies credential stores and leaves ordinary paths alone', () => {
    expect(classifySensitivePath('/home/u/.ssh/id_ed25519')).toHaveLength(1);
    expect(classifySensitivePath('/home/u/.aws/credentials')).toHaveLength(1);
    expect(classifySensitivePath('/home/u/.claude/skills/sshlink')).toEqual([]);
  });

  it('covers the other credential stores a config-set tree must never reach', () => {
    for (const p of ['/home/u/.config/gh/hosts.yml', '/home/u/.config/gcloud', '/home/u/.azure/x', '/home/u/.password-store',
      '/Users/u/Library/Keychains/login.keychain-db', '/home/u/.codex/auth.json', '/home/u/.netrc', '/home/u/.git-credentials',
      '/Users/u/Library/Application Support/Google/Chrome/Default', '/home/u/.mozilla/firefox', '/home/u/.config/chromium']) {
      expect(classifySensitivePath(p), p).toHaveLength(1);
      expect(isCredentialPath(p), p).toBe(true);
    }
    // a Codex skills dir is not its credential store
    for (const p of ['/home/u/.codex/skills/x', '/home/u/.config/ghostty', '/home/u/.github/x']) expect(classifySensitivePath(p), p).toEqual([]);
  });

  it('covers other tools\' credential files, the GNOME keyring and typed-command history', () => {
    for (const p of ['/home/u/.vault-token', '/home/u/.my.cnf', '/home/u/.mylogin.cnf', '/home/u/.s3cfg', '/home/u/.boto',
      '/home/u/.cargo/credentials.toml', '/home/u/.cargo/credentials', '/home/u/.config/rclone/rclone.conf',
      '/home/u/.terraform.d/credentials.tfrc.json', '/home/u/.local/share/keyrings/login.keyring',
      '/home/u/.zsh_history', '/home/u/.bash_history', '/home/u/.psql_history', '/Users/u/.zsh_sessions/x.history',
      '/home/u/.local/share/fish/fish_history', '/home/u/.histfile', '/home/u/.irb_history', '/home/u/.ksh_history',
      '/home/u/.Rhistory', '/home/u/.lesshst', '/home/u/.history', '/home/u/.node-repl-history', '/home/u/.sqlite_history']) {
      expect(classifySensitivePath(p), p).toHaveLength(1);
    }
    for (const p of ['/home/u/.vault-token', '/home/u/.cargo/credentials.toml', '/home/u/.config/rclone/rclone.conf', '/home/u/.local/share/keyrings/x']) {
      expect(isCredentialPath(p), p).toBe(true);
    }
    expect(credentialStoreOf('/home/u/.local/share/keyrings/cop/config.json')).toBeDefined();
    // look-alikes and agents' own files stay ordinary
    for (const p of ['/home/u/.cargo/config.toml', '/home/u/.config/rclone/filters.txt', '/home/u/proj/history.md',
      '/home/u/.claude/history.jsonl', '/home/u/.local/share/opencode/x', '/home/u/my.cnf.d/readme',
      '/home/u/.copilot/command-history-state.json', '/home/u/.gemini/shell_history', '/home/u/.histfile.bak', '/home/u/.history/x']) {
      expect(classifySensitivePath(p), p).toEqual([]);
    }
  });

  it("covers every agent token store the probe manifest ships as metadata only", async () => {
    // The manifest's metadata-only globs are the list of agent credential
    // files; a skills tree reaching one through a link (or a linked root)
    // must not read or ship it either — both sides judge by SENSITIVE_SINKS
    const { buildProbeManifest } = await import('../core/manifest-builder.js');
    const { allAdapters } = await import('../adapters/index.js');
    const globs = buildProbeManifest(allAdapters).metadataGlobPatterns ?? [];
    const credential = /(?:^|\/)(?:[^/]*(?:auth|credential|oauth|token|secret|google_accounts|keystore|mtls|device-key)[^/]*|\.secret_key)(?:\/\*\*?)?$/i;
    // Copilot's mcp-secrets / mcp-oauth-config are private stores (store-links.ts)
    const pnpmOrBin = /\/pnpm\/|\/bin\/|\/\.copilot\//;
    const checked: string[] = [];
    for (const g of globs) {
      if (!g.startsWith('~/') || pnpmOrBin.test(g) || !credential.test(g)) continue;
      // one concrete path per glob: `{a,b}` → a, `*`/`**` → a name
      const p = g.replace('~', '/home/u').replace(/\{([^,}]+)[^}]*\}/g, '$1').replace(/\*\*?/g, 'x').replace(/\/x$/, '/x');
      checked.push(p);
      expect(classifySensitivePath(p), `${g} → ${p}`).not.toEqual([]);
      expect(isCredentialPath(p), p).toBe(true);
    }
    for (const p of ['/home/u/.claude/.credentials.json', '/home/u/.codex/auth.json', '/home/u/.local/share/opencode/auth.json',
      '/home/u/.gemini/oauth_creds.json', '/home/u/.local/share/devin/credentials.toml']) {
      expect(checked, p).toContain(p);
    }
    // Their directories are not: `~/.claude` as a scope or a skills root is judged elsewhere
    for (const p of ['/home/u/.claude', '/home/u/.claude/skills/x/SKILL.md', '/home/u/.gemini/settings.json', '/home/u/.copilot/config.json',
      '/home/u/.hermes/config.yaml', '/home/u/.openclaw/openclaw.json', '/home/u/.grokbot/settings.json']) {
      expect(classifySensitivePath(p), p).toEqual([]);
    }
  });
});

describe('isCredentialPath (skill read sources, dt17)', () => {
  it('credential stores by directory or by file name, relative or absolute', () => {
    for (const p of ['/home/user/.ssh/id_rsa', '~/.aws/credentials'.replace('~', '/home/u'), '.env', '/home/u/.npmrc', '/r/.git-credentials', '/x/.docker/config.json', '/k/.kube/config', 'id_ed25519']) {
      expect(isCredentialPath(p), p).toBe(true);
    }
  });
  it('ordinary files, shell startup files and the rest of /etc are not credential reads', () => {
    for (const p of ['/home/u/.config/myskill/settings.json', 'template.txt', '/home/u/.bashrc', '/etc/os-release', 'docs/credentials-guide.md', '--env']) {
      expect(isCredentialPath(p), p).toBe(false);
    }
  });
});
