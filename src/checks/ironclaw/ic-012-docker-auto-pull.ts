import type { Evidence, FixResult } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { updateConfigValue, updateEnvFile } from '../../remediation/config-writer.js';
import { falsy, isLegacy, isLegacyUnused, legacySetting, str, truthy } from './layout.js';

/*
 * 0.x only: the sandbox worker image is SANDBOX_IMAGE / [sandbox].image
 * (default `ironclaw-worker:latest`, a locally built tag) and
 * SANDBOX_AUTO_PULL / [sandbox].auto_pull_image (default true) pulls it when
 * missing. A registry image pulled by mutable tag lets whoever controls the
 * tag swap the code that runs every tool. Only explicit settings are judged —
 * the stock local default is not a finding. (SANDBOX_DOCKER_IMAGE, which this
 * check used to read, never existed.)
 */

const DEFAULT_IMAGE = 'ironclaw-worker:latest';

export const ic012 = defineCheck({
  id: 'IC-012',
  name: 'Sandbox Image Pulled Without Digest Pin (0.x)',
  category: 'ironclaw',
  severity: 'warning',
  description: 'Check if IronClaw 0.x auto-pulls the sandbox worker image (SANDBOX_AUTO_PULL) by a mutable tag instead of an @sha256 digest',
  supportedAgents: ['ironclaw'],

  async run(ctx, h) {
    if (!isLegacy(ctx)) return h.passed('Not applicable to IronClaw 1.x');
    if (isLegacyUnused(ctx)) return h.passed('0.x configuration is not used by the installed IronClaw 1.x binary');

    const pull = legacySetting(ctx, 'SANDBOX_AUTO_PULL', 'sandbox.auto_pull_image');
    const image = legacySetting(ctx, 'SANDBOX_IMAGE', 'sandbox.image');
    if (pull.some(s => falsy(s.value))) return h.passed('Sandbox image auto-pull is disabled');

    const explicitPull = pull.find(s => truthy(s.value));
    const explicitImage = image.find(s => !!str(s.value));
    if (!explicitPull && !explicitImage) return h.passed('Sandbox image uses the default local build');

    const imageRef = str(explicitImage?.value) ?? DEFAULT_IMAGE;
    if (imageRef.includes('@sha256:')) return h.passed('Sandbox image is pinned by digest');

    const evidence: Evidence[] = [{
      file: (explicitImage ?? explicitPull)!.file,
      detail: `Sandbox image "${imageRef}" is auto-pulled by tag (no @sha256: digest) — a mutated tag replaces the code that runs every sandboxed tool`,
    }];
    return h.fromEvidence(evidence, {
      passed: 'Sandbox image is pinned or not auto-pulled',
      failed: () => 'Sandbox image is auto-pulled without a digest pin',
      fixable: true,
      fixDescription: 'Pin SANDBOX_IMAGE to an @sha256: digest, or set SANDBOX_AUTO_PULL=false and pre-pull a verified image',
    });
  },

  async fix(ctx): Promise<FixResult> {
    if (!isLegacy(ctx) || isLegacyUnused(ctx)) return { checkId: 'IC-012', applied: false, message: 'Not applicable' };
    const pull = legacySetting(ctx, 'SANDBOX_AUTO_PULL', 'sandbox.auto_pull_image');
    const target = pull.find(s => truthy(s.value));
    if (target && target.config.format !== 'env') {
      await updateConfigValue(target.config, 'sandbox.auto_pull_image', false);
      return { checkId: 'IC-012', applied: true, message: 'Set [sandbox].auto_pull_image = false' };
    }
    const env = ctx.configs.find(c => c.format === 'env');
    if (env) {
      await updateEnvFile(env.filePath, 'SANDBOX_AUTO_PULL', 'false');
      return { checkId: 'IC-012', applied: true, message: 'Set SANDBOX_AUTO_PULL=false' };
    }
    return { checkId: 'IC-012', applied: false, message: 'No .env file to write SANDBOX_AUTO_PULL into' };
  },
});
