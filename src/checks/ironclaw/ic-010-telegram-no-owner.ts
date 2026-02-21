import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const ic010: CheckModule = {
  id: 'IC-010',
  name: 'Telegram Without Owner ID',
  category: 'ironclaw',
  severity: 'warning',
  description: 'Check if Telegram integration is enabled but TELEGRAM_OWNER_ID is not set',
  supportedAgents: ['ironclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];

    for (const config of ctx.configs) {
      const telegramToken =
        (config.data.TELEGRAM_TOKEN as string | undefined) ??
        (getNestedValue(config.data, 'telegram.token') as string | undefined);

      const telegramOwnerId =
        (config.data.TELEGRAM_OWNER_ID as string | undefined) ??
        (getNestedValue(config.data, 'telegram.owner_id') as string | undefined) ??
        (getNestedValue(config.data, 'telegram.ownerId') as string | undefined);

      if (telegramToken && telegramToken.trim() !== '') {
        if (!telegramOwnerId || telegramOwnerId.trim() === '') {
          evidence.push({
            file: config.filePath,
            detail: 'Telegram is enabled (TELEGRAM_TOKEN set) but TELEGRAM_OWNER_ID is empty — any Telegram user can interact with the bot',
          });
        }
      }
    }

    return {
      id: 'IC-010',
      name: 'Telegram Without Owner ID',
      category: 'ironclaw',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Telegram owner ID is properly configured or Telegram is not enabled'
        : 'Telegram is enabled without an owner ID — bot is accessible to any user',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true,
      fixDescription: 'Set TELEGRAM_OWNER_ID to your Telegram user ID in .env or telegram.owner_id in config.toml',
    };
  },
};
