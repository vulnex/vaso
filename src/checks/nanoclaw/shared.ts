import { dirname, join } from 'node:path';
import type { Evidence, ParsedConfig, ScanContext, Severity } from '../../core/types.js';
import { isNanoclawCheckout, nanoclawConfigDir } from '../../adapters/nanoclaw.js';

/** `<checkout>` when the installation is a NanoClaw v2 checkout, else undefined. */
export function checkoutDir(ctx: ScanContext): string | undefined {
  const dir = ctx.installation.installDir;
  return isNanoclawCheckout(dir) ? dir : undefined;
}

export function allowlistConfig(ctx: ScanContext): ParsedConfig | undefined {
  return ctx.configs.find(c => c.filePath.endsWith('/mount-allowlist.json') || c.filePath === 'mount-allowlist.json');
}

/** `<checkout>/.env` parsed data (empty when absent). */
export function checkoutEnv(ctx: ScanContext): { data: Record<string, unknown>; file?: string } {
  const dir = checkoutDir(ctx);
  if (!dir) return { data: {} };
  const path = join(dir, '.env');
  const cfg = ctx.configs.find(c => c.filePath === path);
  return cfg ? { data: cfg.data ?? {}, file: path } : { data: {} };
}

/** ~/.config/nanoclaw for this installation's user. */
export function hostConfigDir(ctx: ScanContext): string {
  const allowlist = allowlistConfig(ctx);
  if (allowlist) return dirname(allowlist.filePath);
  const dir = ctx.installation.installDir;
  if (!isNanoclawCheckout(dir)) return dir;
  return nanoclawConfigDir(ctx.fs.homedir());
}

const RANK: Record<Severity, number> = { info: 0, warning: 1, critical: 2 };

export function maxSeverity(items: Severity[], fallback: Severity): Severity {
  if (items.length === 0) return fallback;
  return items.reduce((a, b) => (RANK[b] > RANK[a] ? b : a));
}

/**
 * Evidence + severity accumulator that respects parent-dir mitigation.
 * Convention for "other users can touch this" findings: world access carries
 * the check's severity; group-only access is 'info' — on the common
 * user-private-group layout (Debian/Ubuntu umask 002) the group is the owner
 * alone, which mode bits cannot confirm.
 */
export class Findings {
  readonly evidence: Evidence[] = [];
  private readonly severities: Severity[] = [];

  add(e: Evidence, severity: Severity): void {
    this.evidence.push(e);
    this.severities.push(severity);
  }

  /** Highest severity among un-mitigated items (all mitigated → fromEvidence drops to info). */
  severity(fallback: Severity): Severity {
    const live = this.severities.filter((_, i) => !this.evidence[i].mitigated);
    return maxSeverity(live.length > 0 ? live : this.severities, fallback);
  }
}

/** Suffix for group-only findings (`world` = the exposure also reaches every user). */
export function groupOnlyNote(world: boolean): string {
  return world
    ? ''
    : ' (group only — harmless under a user-private group; tighten if the group is shared)';
}
