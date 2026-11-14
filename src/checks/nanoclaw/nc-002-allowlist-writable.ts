import { join } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';
import { markUnreachable, queryPermissions } from '../../core/permissions.js';
import { restrictFilesToOwner } from '../../remediation/config-writer.js';
import { NANOCLAW_HOST_SECRET_FILES } from '../../adapters/nanoclaw.js';
import { Findings, groupOnlyNote, hostConfigDir } from './shared.js';

/**
 * ~/.config/nanoclaw holds the mount allowlist — deliberately outside the
 * checkout so agents cannot edit the rules that govern them — plus the
 * community-portal identity: account.json / registry-auth.json (install
 * tokens) and device-key.json (device private key). Upstream writes the
 * secrets 0600 under a 0700 dir, but `setup --step mounts` creates the dir and
 * the allowlist with the process umask (0775/0664 on Debian/Ubuntu).
 */
export const nc002 = defineCheck({
  id: 'NC-002',
  name: 'Mount Allowlist / Host Config Exposed',
  category: 'nanoclaw',
  severity: 'critical',
  description: 'Verify ~/.config/nanoclaw and mount-allowlist.json are not writable by other users (a writable allowlist grants agents more host filesystem), and that account.json, registry-auth.json and device-key.json are not readable by other users.',
  supportedAgents: ['nanoclaw'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const dir = hostConfigDir(ctx);
    const findings = new Findings();

    const writable = [
      { path: dir, what: 'config directory (its entries, including the allowlist, can be replaced)' },
      { path: join(dir, 'mount-allowlist.json'), what: 'mount allowlist' },
    ];
    for (const { path, what } of writable) {
      try {
        const perms = await queryPermissions(ctx.fs, path);
        if (perms === 'unsupported' || !(perms.groupWrite || perms.worldWrite)) continue;
        findings.add(
          { file: path, detail: `Permissions ${perms.octal ?? perms.description} — ${what} writable by ${perms.worldWrite ? 'any local user' : 'the group'}${groupOnlyNote(perms.worldWrite)}` },
          perms.worldWrite ? 'critical' : 'info',
        );
      } catch {
        // absent
      }
    }

    for (const name of NANOCLAW_HOST_SECRET_FILES) {
      const path = join(dir, name);
      try {
        const perms = await queryPermissions(ctx.fs, path);
        if (perms === 'unsupported' || !(perms.groupRead || perms.worldRead)) continue;
        findings.add(
          { file: path, detail: `Permissions ${perms.octal ?? perms.description} — ${name} (install token / device key) readable by ${perms.worldRead ? 'any local user' : 'the group'}${groupOnlyNote(perms.worldRead)}` },
          perms.worldRead ? 'critical' : 'info',
        );
      } catch {
        // absent
      }
    }

    await markUnreachable(ctx.fs, findings.evidence);
    return h.fromEvidence(findings.evidence, {
      passed: 'NanoClaw host config (mount allowlist, identity files) is owner-only',
      failed: (n) => `${n} NanoClaw host config path${n === 1 ? ' is' : 's are'} accessible to other users`,
      severity: findings.severity('critical'),
      fixable: true,
      fixDescription: 'Remove group/other access from ~/.config/nanoclaw and mount-allowlist.json, account.json, registry-auth.json, device-key.json (chmod go-rwx)',
    });
  },

  async fix(ctx) {
    const dir = hostConfigDir(ctx);
    // group/other bits cleared, never a fixed 700/600 (a 0400 file keeps no write)
    return restrictFilesToOwner('NC-002', [dir, ...['mount-allowlist.json', ...NANOCLAW_HOST_SECRET_FILES].map(n => join(dir, n))]);
  },
});
