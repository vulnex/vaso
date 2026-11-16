import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUnreachable, queryPermissions, writableByOthers } from '../../core/permissions.js';
import { restrictFilesToOwner } from '../../remediation/config-writer.js';
import { DATA_FILES } from '../../adapters/grok-bot.js';
import { dataFile } from './shared.js';
import { permissionFixTargets } from '../../remediation/fix-refusal.js';

interface Target {
  path: string;
  level: 'critical' | 'warning';
  holds: string;
  dir?: boolean;
}

/**
 * The exec daemon decides what the cloud agent may do here from files in the
 * data root (0.78.4 permission engine): settings.json ("Execution on Local
 * Computer", Messages, Mail sending), pending approvals, standing grants, the
 * spent single-use send approvals and withdrawn approvals, and the server-
 * mirrored computer-use and device-tool gates. Anyone who can write them can
 * approve actions for the cloud agent; the app creates them 0600 in a 0700
 * dir, so this only fires on a loosened mode.
 */
function targets(ctx: ScanContext): Target[] {
  return [
    { path: ctx.installation.installDir, level: 'critical', holds: 'every Grok Bot setting and approval (files can be replaced)', dir: true },
    { path: dataFile(ctx, DATA_FILES.settings), level: 'critical', holds: '"Execution on Local Computer", Messages and Mail settings' },
    { path: dataFile(ctx, DATA_FILES.approvals), level: 'critical', holds: 'approvals the daemon honours for pending actions' },
    { path: dataFile(ctx, DATA_FILES.standingGrants), level: 'critical', holds: 'standing "Always allow" grants' },
    { path: dataFile(ctx, DATA_FILES.spentSends), level: 'warning', holds: 'the record of spent single-use send approvals (clearing it lets an approval be replayed)' },
    { path: dataFile(ctx, DATA_FILES.retirements), level: 'warning', holds: 'withdrawn approvals (clearing it revives them)' },
    { path: dataFile(ctx, DATA_FILES.computerUseGate), level: 'warning', holds: 'the computer-use gate the daemon reads' },
    { path: dataFile(ctx, DATA_FILES.macDeviceToolsGate), level: 'warning', holds: 'the Mac device-tools gate the daemon reads' },
  ];
}

export const gb015 = defineCheck({
  id: 'GB-015',
  name: 'Grok Bot Approval State Writable by Others',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Check that other local users cannot write Grok Bot\'s data root, settings.json, pending approvals or standing grants (critical — they could approve commands, file access, Messages or Mail for the cloud agent), or the spent-send and withdrawn-approval records and the computer-use / device-tool gates (warning)',
  supportedAgents: ['grok-bot'],
  supportedPlatforms: ['darwin', 'linux'],

  fixTargets: permissionFixTargets,

  async run(ctx, h) {
    const critical: Evidence[] = [];
    const warning: Evidence[] = [];
    for (const t of targets(ctx)) {
      try {
        if (!(await ctx.fs.access(t.path))) continue;
        const perms = await queryPermissions(ctx.fs, t.path);
        if (perms === 'unsupported' || !writableByOthers(perms)) continue;
        (t.level === 'critical' ? critical : warning).push({ file: t.path, snippet: `mode 0${perms.octal}`, detail: `${t.dir ? 'Directory with' : 'Holds'} ${t.holds} — writable by group or other users` });
      } catch {
        // can't stat — skip
      }
    }
    await markUnreachable(ctx.fs, critical);
    await markUnreachable(ctx.fs, warning);
    const files = new Set(targets(ctx).filter(t => !t.dir).map(t => t.path));
    return h.fromEvidence([...critical, ...warning], {
      passed: 'Grok Bot settings and approvals are writable only by their owner',
      failed: (n) => `Found ${n} Grok Bot approval-state path(s) writable by other users`,
      severity: critical.some(e => !e.mitigated) || warning.length === 0 ? undefined : 'warning',
      fixable: [...critical, ...warning].some(e => files.has(e.file ?? '')),
      fixDescription: 'chmod go-rwx the flagged Grok Bot files (vaso fix does this) and chmod 700 the data root, then review settings.json, local-tool-approvals.json and local-tool-standing-grants.v1.json for changes you did not make',
    });
  },

  async fix(ctx) {
    return restrictFilesToOwner('GB-015', targets(ctx).filter(t => !t.dir).map(t => t.path));
  },
});
