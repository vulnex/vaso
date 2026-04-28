import { describe, it, expect } from 'vitest';
import type { ParsedConfig } from '../core/types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { openclawAdapter } from './openclaw.js';
import { nemoclawAdapter } from './nemoclaw.js';
import { claudeCodeAdapter } from './claude-code.js';
import { codexAdapter } from './codex.js';
import { nanobotAdapter } from './nanobot.js';

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
});
