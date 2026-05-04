import { describe, it, expect } from 'vitest';
import type { ParsedConfig } from '../core/types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { openclawAdapter } from './openclaw.js';
import { nemoclawAdapter } from './nemoclaw.js';
import { claudeCodeAdapter } from './claude-code.js';
import { codexAdapter } from './codex.js';
import { opencodeAdapter } from './opencode.js';
import { nanobotAdapter } from './nanobot.js';
import { hermesAdapter } from './hermes.js';
import { ironclawAdapter } from './ironclaw.js';
import { lyrieAdapter } from './lyrie.js';
import { nanoclawAdapter } from './nanoclaw.js';
import { picoclawAdapter } from './picoclaw.js';
import { zeroclawAdapter } from './zeroclaw.js';

function cfg(filePath: string, data: Record<string, unknown>): ParsedConfig {
  return { raw: '', format: 'json', filePath, data };
}

function fsWithEnv(env: Record<string, string> = {}): FSProvider {
  return {
    getEnv: (key: string) => env[key],
  } as unknown as FSProvider;
}

describe('adapter.getModels()', () => {
  describe('openclaw', () => {
    it('flattens models.providers.<provider>.models[] to ModelRef[]', () => {
      const configs = [
        cfg('/u/.openclaw/openclaw.json', {
          models: {
            providers: {
              ollama: {
                models: [
                  { id: 'glm-4.7-flash' },
                  { id: 'qwen3.5:9b', name: 'qwen3.5:9b' },
                ],
              },
              openai: {
                models: [{ name: 'gpt-4o' }],
              },
            },
          },
        }),
      ];
      const out = openclawAdapter.getModels!(configs);
      expect(out).toEqual([
        { id: 'glm-4.7-flash', provider: 'ollama' },
        { id: 'qwen3.5:9b', provider: 'ollama' },
        { id: 'gpt-4o', provider: 'openai' },
      ]);
    });

    it('returns [] when no models block present', () => {
      const configs = [cfg('/u/.openclaw/openclaw.json', { meta: {} })];
      expect(openclawAdapter.getModels!(configs)).toEqual([]);
    });
  });

  describe('nemoclaw', () => {
    it('extracts per-sandbox model with provider and via=sandbox-name', () => {
      const configs = [
        cfg('/u/.nemoclaw/sandboxes.json', {
          sandboxes: {
            'my-assistant': { model: 'nvidia/nemotron-3-super-120b-a12b', provider: 'nvidia-nim' },
            'helper': { model: 'meta/llama-3.1-70b', provider: 'nvidia-nim' },
          },
        }),
      ];
      expect(nemoclawAdapter.getModels!(configs)).toEqual([
        { id: 'nvidia/nemotron-3-super-120b-a12b', provider: 'nvidia-nim', via: 'my-assistant' },
        { id: 'meta/llama-3.1-70b', provider: 'nvidia-nim', via: 'helper' },
      ]);
    });

    it('skips sandboxes without a model field', () => {
      const configs = [
        cfg('/u/.nemoclaw/sandboxes.json', { sandboxes: { foo: { provider: 'nvidia-nim' } } }),
      ];
      expect(nemoclawAdapter.getModels!(configs)).toEqual([]);
    });
  });

  describe('claude-code', () => {
    it('reads model from settings.json with anthropic provider', () => {
      const configs = [cfg('/u/.claude/settings.json', { model: 'sonnet' })];
      expect(claudeCodeAdapter.getModels!(configs)).toEqual([
        { id: 'sonnet', provider: 'anthropic' },
      ]);
    });

    it('records fallback model with via=fallback', () => {
      const configs = [
        cfg('/u/.claude/settings.json', { model: 'opus', fallbackModel: 'sonnet' }),
      ];
      expect(claudeCodeAdapter.getModels!(configs)).toEqual([
        { id: 'opus', provider: 'anthropic' },
        { id: 'sonnet', provider: 'anthropic', via: 'fallback' },
      ]);
    });

    it('returns [] when settings has no model field and no other signals', () => {
      const configs = [cfg('/u/.claude/settings.json', { hooks: {} })];
      expect(claudeCodeAdapter.getModels!(configs)).toEqual([]);
    });

    it('falls back to ~/.claude.json top-level model', () => {
      const configs = [
        cfg('/u/.claude/settings.json', {}),
        cfg('/u/.claude.json', { model: 'claude-haiku-4-5' }),
      ];
      expect(claudeCodeAdapter.getModels!(configs)).toEqual([
        { id: 'claude-haiku-4-5', provider: 'anthropic' },
      ]);
    });

    it('uses ANTHROPIC_MODEL env var when no settings model', () => {
      const configs = [cfg('/u/.claude/settings.json', {})];
      expect(claudeCodeAdapter.getModels!(configs, fsWithEnv({ ANTHROPIC_MODEL: 'claude-sonnet-4-7' }))).toEqual([
        { id: 'claude-sonnet-4-7', provider: 'anthropic', via: 'ANTHROPIC_MODEL' },
      ]);
    });

    it('infers opus plan default from migration flags', () => {
      const configs = [
        cfg('/u/.claude/settings.json', {}),
        cfg('/u/.claude.json', { hasOpusPlanDefault: true, opus45MigrationComplete: true }),
      ];
      expect(claudeCodeAdapter.getModels!(configs)).toEqual([
        { id: 'claude-opus-4.5', provider: 'anthropic', via: 'plan default' },
      ]);
    });

    it('infers opus 4.7 when opus47MigrationComplete is set', () => {
      const configs = [
        cfg('/u/.claude/settings.json', {}),
        cfg('/u/.claude.json', { hasOpusPlanDefault: true, opus47MigrationComplete: true }),
      ];
      expect(claudeCodeAdapter.getModels!(configs)).toEqual([
        { id: 'claude-opus-4.7', provider: 'anthropic', via: 'plan default' },
      ]);
    });

    it('infers sonnet plan default when no opus signal', () => {
      const configs = [
        cfg('/u/.claude/settings.json', {}),
        cfg('/u/.claude.json', { sonnet45MigrationComplete: true }),
      ];
      expect(claudeCodeAdapter.getModels!(configs)).toEqual([
        { id: 'claude-sonnet-4.5', provider: 'anthropic', via: 'plan default' },
      ]);
    });

    it('explicit settings.model wins over env var and plan inference', () => {
      const configs = [
        cfg('/u/.claude/settings.json', { model: 'opus' }),
        cfg('/u/.claude.json', { hasOpusPlanDefault: true, opus45MigrationComplete: true }),
      ];
      expect(
        claudeCodeAdapter.getModels!(configs, fsWithEnv({ ANTHROPIC_MODEL: 'sonnet' })),
      ).toEqual([{ id: 'opus', provider: 'anthropic' }]);
    });
  });

  describe('codex', () => {
    it('reads top-level model + model_provider from config.toml', async () => {
      const configs = [
        cfg('/u/.codex/config.toml', { model: 'gpt-5.4', model_provider: 'openai' }),
      ];
      expect(await codexAdapter.getModels!(configs)).toEqual([
        { id: 'gpt-5.4', provider: 'openai' },
      ]);
    });

    it('returns [] when config.toml lacks model and no fs available', async () => {
      const configs = [cfg('/u/.codex/config.toml', { trust_level: 'trusted' })];
      expect(await codexAdapter.getModels!(configs)).toEqual([]);
    });

    it('falls back to latest session jsonl when config.toml has no model', async () => {
      // Synthesize a minimal FSProvider that walks a fake sessions tree:
      // /home/u/.codex/sessions/2026/04/18/rollout-2026-04-18T22-06.jsonl
      // and an older 2026/04/17 one to confirm we pick the lex-latest.
      const tree: Record<string, string[]> = {
        '/home/u/.codex/sessions': ['2025', '2026'],
        '/home/u/.codex/sessions/2026': ['03', '04'],
        '/home/u/.codex/sessions/2026/04': ['17', '18'],
        '/home/u/.codex/sessions/2026/04/17': ['rollout-2026-04-17T09-00-x.jsonl'],
        '/home/u/.codex/sessions/2026/04/18': [
          'rollout-2026-04-18T10-00-a.jsonl',
          'rollout-2026-04-18T22-06-z.jsonl',
        ],
      };
      const files: Record<string, string> = {
        '/home/u/.codex/sessions/2026/04/18/rollout-2026-04-18T22-06-z.jsonl':
          '{"type":"turn_context","payload":{"model":"gpt-4o-mini"}}\n' +
          '{"type":"turn_context","payload":{"model":"gpt-5-codex"}}\n',
      };
      const fakeFs = {
        homedir: () => '/home/u',
        async readdirEntries(p: string) {
          const names = tree[p];
          if (!names) throw new Error(`ENOENT ${p}`);
          return names.map(n => ({
            name: n,
            isFile: !tree[`${p}/${n}`],
            isDirectory: !!tree[`${p}/${n}`],
          }));
        },
        async readFile(p: string) {
          if (!(p in files)) throw new Error(`ENOENT ${p}`);
          return files[p];
        },
      } as unknown as FSProvider;
      expect(await codexAdapter.getModels!([], fakeFs)).toEqual([
        { id: 'gpt-5-codex', via: 'last session' },
      ]);
    });

    it('returns [] when sessions tree exists but has no rollout files', async () => {
      const fakeFs = {
        homedir: () => '/home/u',
        async readdirEntries() { return []; },
        async readFile() { throw new Error('ENOENT'); },
      } as unknown as FSProvider;
      expect(await codexAdapter.getModels!([], fakeFs)).toEqual([]);
    });
  });

  describe('opencode', () => {
    it('splits provider/id from top-level model', () => {
      const configs = [
        cfg('/u/.config/opencode/opencode.json', { model: 'anthropic/claude-opus-4-5' }),
      ];
      expect(opencodeAdapter.getModels!(configs)).toEqual([
        { id: 'claude-opus-4-5', provider: 'anthropic' },
      ]);
    });

    it('records small_model with via=small_model', () => {
      const configs = [
        cfg('/u/.config/opencode/opencode.json', {
          model: 'anthropic/claude-opus-4-5',
          small_model: 'anthropic/claude-haiku-4-5',
        }),
      ];
      expect(opencodeAdapter.getModels!(configs)).toEqual([
        { id: 'claude-opus-4-5', provider: 'anthropic' },
        { id: 'claude-haiku-4-5', provider: 'anthropic', via: 'small_model' },
      ]);
    });

    it('handles bare model without provider slash', () => {
      const configs = [cfg('/u/.config/opencode/opencode.json', { model: 'gpt-4o' })];
      expect(opencodeAdapter.getModels!(configs)).toEqual([{ id: 'gpt-4o' }]);
    });

    it('returns [] when no model field is present', () => {
      const configs = [cfg('/u/.config/opencode/opencode.json', { share: 'manual' })];
      expect(opencodeAdapter.getModels!(configs)).toEqual([]);
    });
  });

  describe('nanobot', () => {
    it('splits provider/id slashes from agents.defaults.model', () => {
      const configs = [
        cfg('/u/.nanobot/config.json', {
          agents: { defaults: { model: 'anthropic/claude-opus-4-5' } },
        }),
      ];
      expect(nanobotAdapter.getModels!(configs)).toEqual([
        { id: 'claude-opus-4-5', provider: 'anthropic' },
      ]);
    });

    it('records per-agent overrides with via=agent-name', () => {
      const configs = [
        cfg('/u/.nanobot/config.json', {
          agents: {
            defaults: { model: 'anthropic/claude-opus-4-5' },
            researcher: { model: 'openai/gpt-4o' },
          },
        }),
      ];
      expect(nanobotAdapter.getModels!(configs)).toEqual([
        { id: 'claude-opus-4-5', provider: 'anthropic' },
        { id: 'gpt-4o', provider: 'openai', via: 'researcher' },
      ]);
    });

    it('handles bare model id without provider slash', () => {
      const configs = [
        cfg('/u/.nanobot/config.json', { agents: { defaults: { model: 'gpt-4o' } } }),
      ];
      expect(nanobotAdapter.getModels!(configs)).toEqual([{ id: 'gpt-4o' }]);
    });
  });

  describe('hermes', () => {
    it('reads cli-config.yaml model.default + sibling provider', async () => {
      const configs = [
        cfg('/u/.hermes/cli-config.yaml', {
          model: {
            default: 'gpt-5.5',
            provider: 'openai-codex',
            base_url: 'https://chatgpt.com/backend-api/codex',
          },
        }),
      ];
      expect(await hermesAdapter.getModels!(configs)).toEqual([
        { id: 'gpt-5.5', provider: 'openai-codex' },
      ]);
    });

    it('also accepts model.model as alias for model.default', async () => {
      const configs = [
        cfg('/u/.hermes/cli-config.yaml', {
          model: { model: 'gpt-5.5', provider: 'openai-codex' },
        }),
      ];
      expect(await hermesAdapter.getModels!(configs)).toEqual([
        { id: 'gpt-5.5', provider: 'openai-codex' },
      ]);
    });

    it('still reads legacy config.yaml when cli-config.yaml absent', async () => {
      const configs = [
        cfg('/u/.hermes/config.yaml', { model: { default: 'anthropic/claude-opus-4.6' } }),
      ];
      expect(await hermesAdapter.getModels!(configs)).toEqual([
        { id: 'claude-opus-4.6', provider: 'anthropic' },
      ]);
    });

    it('keeps slashes in id when explicit provider is given (e.g. nvidia/nemotron)', async () => {
      const configs = [
        cfg('/u/.hermes/cli-config.yaml', {
          model: { default: 'nvidia/nemotron-3-super-120b-a12b', provider: 'nvidia-nim' },
        }),
      ];
      expect(await hermesAdapter.getModels!(configs)).toEqual([
        { id: 'nvidia/nemotron-3-super-120b-a12b', provider: 'nvidia-nim' },
      ]);
    });

    it('records fallback with via=fallback, inheriting provider', async () => {
      const configs = [
        cfg('/u/.hermes/cli-config.yaml', {
          model: { default: 'gpt-5.5', provider: 'openai-codex', fallback: 'gpt-4o' },
        }),
      ];
      expect(await hermesAdapter.getModels!(configs)).toEqual([
        { id: 'gpt-5.5', provider: 'openai-codex' },
        { id: 'gpt-4o', provider: 'openai-codex', via: 'fallback' },
      ]);
    });

    it('handles top-level model as a bare string', async () => {
      const configs = [cfg('/u/.hermes/cli-config.yaml', { model: 'gpt-4o' })];
      expect(await hermesAdapter.getModels!(configs)).toEqual([{ id: 'gpt-4o' }]);
    });

    it('reads HERMES_DEFAULT_MODEL from .env, picking up HERMES_PROVIDER', async () => {
      const configs = [
        cfg('/u/.hermes/.env', {
          HERMES_DEFAULT_MODEL: 'claude-haiku-4-5',
          HERMES_PROVIDER: 'anthropic',
        }),
      ];
      expect(await hermesAdapter.getModels!(configs)).toEqual([
        { id: 'claude-haiku-4-5', provider: 'anthropic' },
      ]);
    });

    it('falls back to process env HERMES_MODEL when nothing in config files', async () => {
      expect(
        await hermesAdapter.getModels!([], fsWithEnv({ HERMES_MODEL: 'openai/gpt-5' })),
      ).toEqual([{ id: 'gpt-5', provider: 'openai', via: 'HERMES_MODEL' }]);
    });

    it('returns [] when no model field in config or env', async () => {
      const configs = [cfg('/u/.hermes/cli-config.yaml', { platforms: {} })];
      expect(await hermesAdapter.getModels!(configs)).toEqual([]);
    });
  });

  describe('ironclaw', () => {
    it('honors LLM_BACKEND from .env to select the matching model env var', async () => {
      const configs = [
        cfg('/u/.ironclaw/.env', {
          LLM_BACKEND: 'openai_codex',
          OPENAI_CODEX_MODEL: 'gpt-5.5',
          ANTHROPIC_MODEL: 'claude-opus-4.6', // present but not selected
        }),
      ];
      expect(await ironclawAdapter.getModels!(configs)).toEqual([
        { id: 'gpt-5.5', provider: 'openai_codex' },
      ]);
    });

    it('uses openai_compatible → LLM_MODEL pairing', async () => {
      const configs = [
        cfg('/u/.ironclaw/.env', {
          LLM_BACKEND: 'openai_compatible',
          LLM_MODEL: 'gpt-4o',
        }),
      ];
      expect(await ironclawAdapter.getModels!(configs)).toEqual([
        { id: 'gpt-4o', provider: 'openai_compatible' },
      ]);
    });

    it('with no LLM_BACKEND, surfaces every populated *_MODEL env var', async () => {
      const configs = [
        cfg('/u/.ironclaw/.env', {
          OPENAI_MODEL: 'gpt-4o',
          ANTHROPIC_MODEL: 'claude-opus-4.6',
        }),
      ];
      expect(await ironclawAdapter.getModels!(configs)).toEqual([
        { id: 'gpt-4o', provider: 'openai', via: 'env-detected' },
        { id: 'claude-opus-4.6', provider: 'anthropic', via: 'env-detected' },
      ]);
    });

    it('falls back to process env when no .env file', async () => {
      expect(
        await ironclawAdapter.getModels!(
          [],
          fsWithEnv({ LLM_BACKEND: 'anthropic', ANTHROPIC_MODEL: 'claude-haiku-4-5' }),
        ),
      ).toEqual([{ id: 'claude-haiku-4-5', provider: 'anthropic' }]);
    });

    it('returns [] when no model env var is populated', async () => {
      const configs = [cfg('/u/.ironclaw/.env', { GATEWAY_PORT: '8080' })];
      expect(await ironclawAdapter.getModels!(configs)).toEqual([]);
    });
  });

  describe('lyrie', () => {
    it('reads LYRIE_MODEL from .env', async () => {
      const configs = [cfg('/u/.lyrie/.env', { LYRIE_MODEL: 'anthropic/claude-opus-4.6' })];
      expect(await lyrieAdapter.getModels!(configs)).toEqual([
        { id: 'claude-opus-4.6', provider: 'anthropic' },
      ]);
    });

    it('records LYRIE_FALLBACK_MODEL with via=fallback', async () => {
      const configs = [
        cfg('/u/.lyrie/.env', {
          LYRIE_DEFAULT_MODEL: 'anthropic/claude-opus-4.6',
          LYRIE_FALLBACK_MODEL: 'openai/gpt-4o',
        }),
      ];
      expect(await lyrieAdapter.getModels!(configs)).toEqual([
        { id: 'claude-opus-4.6', provider: 'anthropic' },
        { id: 'gpt-4o', provider: 'openai', via: 'fallback' },
      ]);
    });

    it('records per-channel LYRIE_<CHANNEL>_MODEL with via=<channel>', async () => {
      const configs = [
        cfg('/u/.lyrie/.env', {
          LYRIE_MODEL: 'anthropic/claude-opus-4.6',
          LYRIE_TELEGRAM_MODEL: 'openai/gpt-4o',
          LYRIE_DISCORD_MODEL: 'google/gemini-2.5-pro',
        }),
      ];
      expect(await lyrieAdapter.getModels!(configs)).toEqual([
        { id: 'claude-opus-4.6', provider: 'anthropic' },
        { id: 'gpt-4o', provider: 'openai', via: 'telegram' },
        { id: 'gemini-2.5-pro', provider: 'google', via: 'discord' },
      ]);
    });

    it('returns [] when no LYRIE_*_MODEL keys present', async () => {
      const configs = [cfg('/u/.lyrie/.env', { ANTHROPIC_API_KEY: 'sk-...' })];
      expect(await lyrieAdapter.getModels!(configs)).toEqual([]);
    });
  });

  describe('nanoclaw', () => {
    it('returns [] — model is delegated to inner CLI via SQLite agent_provider', async () => {
      // NanoClaw doesn't pick a model; it spawns claude/codex/opencode based on
      // a per-session field stored in SQLite. VASO can't reliably surface that.
      const configs = [
        cfg('/u/.config/nanoclaw/config.json', { agents: { defaults: { agent_provider: 'claude' } } }),
      ];
      expect(await nanoclawAdapter.getModels!(configs)).toEqual([]);
    });
  });

  describe('picoclaw', () => {
    it('reads model_list[] entries, surfacing default with no via', async () => {
      const configs = [
        cfg('/u/.picoclaw/config.json', {
          agents: { defaults: { model_name: 'primary' } },
          model_list: [
            { model_name: 'primary', model: 'anthropic/claude-opus-4.6', api_key: 'sk-...' },
            { model_name: 'cheap', model: 'openai/gpt-4o-mini', api_key: 'sk-...' },
          ],
        }),
      ];
      expect(await picoclawAdapter.getModels!(configs)).toEqual([
        { id: 'claude-opus-4.6', provider: 'anthropic' },
        { id: 'gpt-4o-mini', provider: 'openai', via: 'cheap' },
      ]);
    });

    it('dedupes load-balance pool entries with the same model_name + model', async () => {
      const configs = [
        cfg('/u/.picoclaw/config.json', {
          agents: { defaults: { model_name: 'primary' } },
          model_list: [
            { model_name: 'primary', model: 'openai/gpt-5.4', api_key: 'k1', api_base: 'h1' },
            { model_name: 'primary', model: 'openai/gpt-5.4', api_key: 'k2', api_base: 'h2' },
          ],
        }),
      ];
      expect(await picoclawAdapter.getModels!(configs)).toEqual([
        { id: 'gpt-5.4', provider: 'openai' },
      ]);
    });

    it('returns [] when model_list is missing', async () => {
      const configs = [cfg('/u/.picoclaw/config.json', { gateway: {} })];
      expect(await picoclawAdapter.getModels!(configs)).toEqual([]);
    });
  });

  describe('zeroclaw', () => {
    it('reads top-level default_provider + default_model', async () => {
      const configs = [
        cfg('/u/.zeroclaw/config.toml', {
          default_provider: 'anthropic',
          default_model: 'claude-opus-4.6',
        }),
      ];
      expect(await zeroclawAdapter.getModels!(configs)).toEqual([
        { id: 'claude-opus-4.6', provider: 'anthropic' },
      ]);
    });

    it('strips embedded base-URL from default_provider (e.g. anthropic-custom:https://...)', async () => {
      const configs = [
        cfg('/u/.zeroclaw/config.toml', {
          default_provider: 'anthropic-custom:https://api.z.ai/api/anthropic',
          default_model: 'claude-opus-4.6',
        }),
      ];
      expect(await zeroclawAdapter.getModels!(configs)).toEqual([
        { id: 'claude-opus-4.6', provider: 'anthropic-custom' },
      ]);
    });

    it('surfaces model_routes entries with the route name as via', async () => {
      const configs = [
        cfg('/u/.zeroclaw/config.toml', {
          default_provider: 'anthropic',
          default_model: 'claude-opus-4.6',
          model_routes: [
            { name: 'cheap', provider: 'openai', model: 'gpt-4o-mini' },
            { name: 'reasoner', provider: 'openai', model: 'o3-mini' },
          ],
        }),
      ];
      expect(await zeroclawAdapter.getModels!(configs)).toEqual([
        { id: 'claude-opus-4.6', provider: 'anthropic' },
        { id: 'gpt-4o-mini', provider: 'openai', via: 'cheap' },
        { id: 'o3-mini', provider: 'openai', via: 'reasoner' },
      ]);
    });

    it('records [reliability.model_fallbacks] with via=fallback:<slot>', async () => {
      const configs = [
        cfg('/u/.zeroclaw/config.toml', {
          default_provider: 'anthropic',
          default_model: 'claude-opus-4.6',
          reliability: {
            model_fallbacks: {
              primary: ['openai/gpt-4o', 'google/gemini-2.5-pro'],
            },
          },
        }),
      ];
      expect(await zeroclawAdapter.getModels!(configs)).toEqual([
        { id: 'claude-opus-4.6', provider: 'anthropic' },
        { id: 'gpt-4o', provider: 'openai', via: 'fallback:primary' },
        { id: 'gemini-2.5-pro', provider: 'google', via: 'fallback:primary' },
      ]);
    });

    it('falls back to ZEROCLAW_MODEL/PROVIDER process env when nothing in config', async () => {
      expect(
        await zeroclawAdapter.getModels!(
          [],
          fsWithEnv({ ZEROCLAW_MODEL: 'gpt-4o', ZEROCLAW_PROVIDER: 'openai' }),
        ),
      ).toEqual([{ id: 'gpt-4o', provider: 'openai', via: 'ZEROCLAW_MODEL' }]);
    });

    it('returns [] when no model field anywhere', async () => {
      const configs = [cfg('/u/.zeroclaw/config.toml', { server: {} })];
      expect(await zeroclawAdapter.getModels!(configs)).toEqual([]);
    });
  });
});
