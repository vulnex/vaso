import type { AgentType, Platform } from '../core/types.js';
import type { VersionParseOptions } from '../core/semver.js';
import type { Advisory } from './advisory-types.js';

/**
 * Whether an advisory can apply on the scanned host's platform: one limited
 * to Windows (`platforms: ['win32']`) doesn't affect a macOS or Linux install
 * of the same version.
 */
export function advisoryAppliesToPlatform(adv: Advisory, platform: Platform): boolean {
  return !adv.platforms?.length || adv.platforms.includes(platform);
}

/**
 * How an agent's version strings compare against advisory ranges. OpenClaw's
 * npm correction releases (`2026.7.1-1`, published after `2026.7.1`) are
 * post-releases, not prereleases; every other agent keeps plain semver.
 */
export function advisoryVersionOptions(agent: AgentType): VersionParseOptions {
  return agent === 'openclaw' ? { correctionSuffix: true } : {};
}
