import { defineCheck } from '../../core/check-builder.js';
import { updateEnvFile, updateTomlFile } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';

export const ic012 = defineCheck({
  id: 'IC-012',
  name: 'Docker Auto-Pull Without Digest Pin',
  category: 'ironclaw',
  severity: 'warning',
  description: 'Check if SANDBOX_AUTO_PULL is enabled without a sha256 digest pin on the Docker image',
  supportedAgents: ['ironclaw'],

  async run(ctx, h) {
    const evidence = [];

    for (const config of ctx.configs) {
      const autoPull =
        (config.data.SANDBOX_AUTO_PULL as string | undefined) ??
        (getNestedValue(config.data, 'sandbox.auto_pull') as string | boolean | undefined) ??
        (getNestedValue(config.data, 'sandbox.autoPull') as string | boolean | undefined);

      const dockerImage =
        (config.data.SANDBOX_DOCKER_IMAGE as string | undefined) ??
        (getNestedValue(config.data, 'sandbox.docker_image') as string | undefined) ??
        (getNestedValue(config.data, 'sandbox.dockerImage') as string | undefined);

      if (autoPull === true || autoPull === 'true') {
        const hasDigestPin = typeof dockerImage === 'string' && dockerImage.includes('@sha256:');

        if (!hasDigestPin) {
          evidence.push({
            file: config.filePath,
            detail: `SANDBOX_AUTO_PULL=true with image "${dockerImage ?? '(not set)'}" — no @sha256: digest pin, vulnerable to tag mutation attacks`,
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Docker auto-pull is either disabled or uses a pinned image digest',
      failed: () => 'Docker auto-pull is enabled without a sha256 digest pin — vulnerable to tag mutation',
      fixable: true,
      fixDescription: 'Pin SANDBOX_DOCKER_IMAGE to a sha256 digest (e.g., myimage@sha256:abc123...) or disable SANDBOX_AUTO_PULL',
    });
  },

  async fix(ctx) {
    for (const config of ctx.configs) {
      if (config.format === 'env') {
        await updateEnvFile(config.filePath, 'SANDBOX_AUTO_PULL', 'false');
        return { checkId: 'IC-012', applied: true, message: 'Disabled SANDBOX_AUTO_PULL' };
      }
      if (config.format === 'toml') {
        await updateTomlFile(config.filePath, 'sandbox.auto_pull', false);
        return { checkId: 'IC-012', applied: true, message: 'Disabled SANDBOX_AUTO_PULL' };
      }
    }
    return { checkId: 'IC-012', applied: false, message: 'No compatible config file found' };
  },
});
