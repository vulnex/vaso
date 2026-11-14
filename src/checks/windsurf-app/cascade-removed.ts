import type { ScanContext } from '../../core/types.js';
import { parseSemVer, compareVersions } from '../../core/semver.js';

/**
 * Devin Desktop 3.9.19 (2026-09-08) removed Cascade: "Cascade has been
 * removed. Devin Local is now the only agent available in Devin Desktop"
 * (docs.devin.ai/desktop/changelog). Cascade's auto-execution policy, command
 * allowlist and workflow turbo directives are inert from that release on.
 */
export const CASCADE_REMOVED_IN = '3.9.19';

/** Why this installation's Cascade settings are inert, or undefined when Cascade still runs (or the version is unknown). */
export function cascadeRemovedNote(ctx: ScanContext): string | undefined {
  const version = ctx.installation.version;
  if (!version || !parseSemVer(version)) return undefined;
  if (compareVersions(version, CASCADE_REMOVED_IN) < 0) return undefined;
  return `Devin Desktop ${version} has no Cascade (removed in ${CASCADE_REMOVED_IN}) — its Cascade settings have no effect`;
}
