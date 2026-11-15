import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { SENSITIVE_SINKS, classifySensitivePath, isCredentialPath } from './sensitive-paths.js';

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
    expect(SENSITIVE_SINKS.every(s => s.re.flags === 'i')).toBe(true);
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
