import { join } from 'node:path';
import type { Evidence, ScanContext, Severity } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUnreachable, queryPermissions, writableByOthers } from '../../core/permissions.js';
import { DATA_FILES, GROK_BOT_BUNDLE_ID, GROK_BOT_HELPER, GROK_BOT_TEAM_ID, grokBotHome } from '../../adapters/grok-bot.js';
import { dataFile, isOwnSession } from './shared.js';

/**
 * The macOS Computer Use helper (0.78.4): the exec daemon copies the signed
 * helper out of `Grok Bot.app/Contents/Helpers` into ~/.grokbot/computer-use,
 * replacing the copy when its files differ from the bundle's, and launches it
 * with `open`. Nothing checks a code signature — the daemon only compares
 * bytes, and caches the result until it restarts. The helper holds the
 * Accessibility and Screen Recording grants and serves the daemon over the
 * socket named in ~/Library/Application Support/grok-bot-computer-use/
 * service.json. GROK_BOT_SIDECAR_APP, when it names an existing app, replaces
 * the helper outright and skips the copy.
 */

const TEAM_ID_RE = /TeamIdentifier=([A-Z0-9]+)/;
const IDENTIFIER_RE = /^Identifier=([\w.-]+)$/m;

interface Signed { path: string; label: string; identifier: string }

/** Signature problems of one bundle; undefined when codesign can't run. */
async function signatureEvidence(ctx: ScanContext, b: Signed): Promise<Evidence[] | undefined> {
  let info;
  let verify;
  try {
    info = await ctx.fs.exec('codesign', ['-dv', b.path], { timeout: 5000 });
    verify = await ctx.fs.exec('codesign', ['--verify', '--strict', b.path], { timeout: 15000 });
  } catch {
    return undefined;
  }
  // codesign writes its metadata to stderr by design
  const text = `${info.stdout}\n${info.stderr}`;
  const team = TEAM_ID_RE.exec(text)?.[1];
  const id = IDENTIFIER_RE.exec(text)?.[1];
  const out: Evidence[] = [];
  if (!team || !id) {
    out.push({ file: b.path, detail: `${b.label} is unsigned or its signature is unreadable` });
    return out;
  }
  if (team !== GROK_BOT_TEAM_ID) {
    out.push({ file: b.path, snippet: `TeamIdentifier=${team} (expected ${GROK_BOT_TEAM_ID})`, detail: `${b.label} is signed by a different developer — not the vendor's build` });
  }
  if (id !== b.identifier) {
    out.push({ file: b.path, snippet: `Identifier=${id} (expected ${b.identifier})`, detail: `${b.label} carries an unexpected bundle identifier — it may have been swapped` });
  }
  if (verify.exitCode !== 0) {
    out.push({ file: b.path, snippet: 'codesign --verify --strict failed', detail: `${b.label} was modified after signing` });
  }
  return out;
}

export const gb016 = defineCheck({
  id: 'GB-016',
  name: 'Grok Bot App or Computer Use Helper Not Intact',
  category: 'coding-agent',
  severity: 'critical',
  description: 'macOS: verify the Grok Bot app and the Computer Use helper copy it launches from ~/.grokbot/computer-use are signed by the vendor (Team ID DCNK4UB866) and unmodified (local scans; critical), that other users cannot write the helper copy or the service.json naming its socket (warning), and report GROK_BOT_SIDECAR_APP replacing the helper with another app (warning)',
  supportedAgents: ['grok-bot'],
  supportedPlatforms: ['darwin'],

  async run(ctx, h) {
    const critical: Evidence[] = [];
    const warning: Evidence[] = [];
    const info: Evidence[] = [];
    const helperDir = dataFile(ctx, DATA_FILES.computerUseDir);
    const helper = join(helperDir, GROK_BOT_HELPER.app);
    const hasHelper = await ctx.fs.access(helper);

    // Signatures: codesign runs only where the files are (not on snapshots)
    if (ctx.fs.kind !== 'snapshot') {
      const bundles: Signed[] = [];
      const app = ctx.installation.appBundle;
      if (app) {
        bundles.push({ path: app, label: 'Grok Bot.app', identifier: GROK_BOT_BUNDLE_ID });
        const bundled = join(app, 'Contents', 'Helpers', GROK_BOT_HELPER.app);
        if (await ctx.fs.access(bundled)) bundles.push({ path: bundled, label: 'The bundled Computer Use helper', identifier: GROK_BOT_HELPER.bundleId });
      }
      if (hasHelper) bundles.push({ path: helper, label: 'The Computer Use helper copy Grok Bot launches', identifier: GROK_BOT_HELPER.bundleId });
      for (const b of bundles) critical.push(...(await signatureEvidence(ctx, b)) ?? []);
    }

    const support = join(grokBotHome(ctx.installation.installDir, ctx.fs), 'Library', 'Application Support', GROK_BOT_HELPER.supportDir);
    const writable: { path: string; holds: string }[] = [
      { path: helperDir, holds: 'the helper copy Grok Bot launches with Accessibility and Screen Recording access' },
      { path: helper, holds: 'the helper copy Grok Bot launches' },
      { path: join(helper, 'Contents', 'MacOS', GROK_BOT_HELPER.executable), holds: 'the helper executable' },
      { path: support, holds: 'the helper\'s state, including service.json' },
      { path: join(support, GROK_BOT_HELPER.serviceFile), holds: 'the socket path the daemon sends computer-use and device-tool calls to' },
    ];
    for (const t of writable) {
      try {
        if (!(await ctx.fs.access(t.path))) continue;
        const perms = await queryPermissions(ctx.fs, t.path);
        if (perms === 'unsupported' || !writableByOthers(perms)) continue;
        warning.push({ file: t.path, snippet: `mode 0${perms.octal}`, detail: `Holds ${t.holds} — writable by group or other users` });
      } catch {
        // can't stat — skip
      }
    }
    await markUnreachable(ctx.fs, warning);

    const override = isOwnSession(ctx) ? ctx.fs.getEnv('GROK_BOT_SIDECAR_APP')?.trim() : undefined;
    if (override) {
      const exists = await ctx.fs.access(override);
      (exists ? warning : info).push({
        file: '<process env>',
        snippet: `GROK_BOT_SIDECAR_APP=${override}`,
        detail: exists
          ? 'Grok Bot launches this app as its Computer Use helper instead of the signed one in its bundle, without copying or checking it'
          : 'Names no existing app, so Grok Bot ignores it — remove it before it points somewhere',
      });
    }

    const severity: Severity | undefined = critical.length > 0 ? undefined : warning.some(e => !e.mitigated) ? 'warning' : info.length > 0 || warning.length > 0 ? 'info' : undefined;
    return h.fromEvidence([...critical, ...warning, ...info], {
      passed: ctx.fs.kind === 'snapshot'
        ? 'Grok Bot Computer Use helper is writable only by its owner (signatures are checked on local scans)'
        : 'Grok Bot app and Computer Use helper are vendor-signed and intact',
      failed: () => critical.length > 0
        ? 'Grok Bot app or Computer Use helper signature does not match the vendor\'s'
        : 'Grok Bot Computer Use helper can be replaced',
      severity,
      fixDescription: 'Reinstall Grok Bot from the vendor and delete ~/.grokbot/computer-use (the app copies a fresh helper), chmod go-w the flagged paths, unset GROK_BOT_SIDECAR_APP, and review the Accessibility and Screen Recording grants in System Settings → Privacy & Security',
    });
  },
});
