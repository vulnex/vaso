import { describe, it, expect } from 'vitest';
import type { ParsedConfig } from '../core/types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { captureConfigLoadErrors } from '../core/config-loader.js';
import { parseYamlSafe } from '../core/yaml-safe.js';
import { expandHermesEnvRefs, hermesConfigAsWritten, hermesManagedOverlay, normalizeHermesModelKeys, prepareHermesYaml } from './hermes-config.js';
import { hermesDeepMerge, hermesYamlSetting, managedOverride } from './hermes-managed.js';
import { hermesAdapter } from './hermes.js';
import { hermesChecks } from '../checks/hermes/index.js';

const yaml = (raw: string, managed = false): ParsedConfig => ({
  raw,
  format: 'yaml',
  filePath: managed ? '/etc/hermes/config.yaml' : '/h/.hermes/config.yaml',
  data: parseYamlSafe(raw) as Record<string, unknown>,
  ...(managed ? { managed } : {}),
});
const env = (data: Record<string, string>, managed = false): ParsedConfig =>
  ({ raw: '', format: 'env', filePath: managed ? '/etc/hermes/.env' : '/h/.hermes/.env', data, ...(managed ? { managed } : {}) });
const fsWith = (vars: Record<string, string> = {}): FSProvider => ({ getEnv: (k: string) => vars[k] } as unknown as FSProvider);

describe('Hermes config.yaml ${VAR} expansion (_expand_env_vars)', () => {
  const lookup = (name: string) => ({ MODE: 'off', EP: 'http://10.1.2.3/v1', ' MODE ': 'spaced' } as Record<string, string>)[name];

  it('expands string values in mappings and lists, never keys; unresolvable refs stay as written', () => {
    const out = expandHermesEnvRefs({ a: '${MODE}', b: ['x-${EP}'], '${MODE}': 1, c: '${NOPE}', n: 5 }, lookup);
    expect(out).toEqual({ a: 'off', b: ['x-http://10.1.2.3/v1'], '${MODE}': 1, c: '${NOPE}', n: 5 });
  });

  it('0.19.1+: trims names, reads ${env:VAR}, keeps other sources; earlier releases look the text up as is', () => {
    expect(expandHermesEnvRefs('${ MODE }|${env:MODE}|${vault:MODE}', lookup, '0.21.6')).toBe('off|off|${vault:MODE}');
    expect(expandHermesEnvRefs('${ MODE }|${env:MODE}', lookup, '0.19.0')).toBe('spaced|${env:MODE}');
    // No default syntax in any release
    expect(expandHermesEnvRefs('${UNSET:-manual}', lookup, '0.21.6')).toBe('${UNSET:-manual}');
  });

  it('resolves from the managed .env, then the user .env, then the process environment', () => {
    const user = yaml('a: ${A}\nb: ${B}\nc: ${C}\n');
    const configs = [user, env({ A: 'user', B: 'user' }), env({ A: 'managed' }, true)];
    prepareHermesYaml(configs, fsWith({ A: 'shell', B: 'shell', C: 'shell' }), '0.21.6');
    expect(user.data).toEqual({ a: 'managed', b: 'user', c: 'shell' });
  });

  it('keeps what the file says for checks about the file itself (HM-001)', async () => {
    const user = yaml('model:\n  api_key: ${KEY}\n');
    prepareHermesYaml([user, env({ KEY: 'sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef' })], fsWith(), '0.21.6');
    expect(user.data).toEqual({ model: { api_key: 'sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef' } });
    expect(hermesConfigAsWritten(user)).toEqual({ model: { api_key: '${KEY}' } });
    const hm001 = hermesChecks.find(c => c.id === 'HM-001')!;
    const ctx = { installation: { agent: 'hermes' as const, installDir: '/h/.hermes', configFiles: [user] }, configs: [user], platform: 'linux' as const, fs: fsWith() };
    expect((await hm001.run(ctx)).passed).toBe(true);
    const plain = yaml('model:\n  api_key: sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef\n');
    prepareHermesYaml([plain], fsWith(), '0.21.6');
    expect((await hm001.run({ ...ctx, configs: [plain] })).passed).toBe(false);
  });
});

describe('Hermes duplicate keys by release', () => {
  const raw = '_config_version: 52\napprovals:\n  mode: manual\napprovals:\n  mode: "off"\n';

  it('0.21.6+ (and an unknown release) rejects the file: CONFIG-LOAD and defaults', async () => {
    for (const version of ['0.21.6', undefined]) {
      const user = yaml(raw);
      const { loadErrors } = await captureConfigLoadErrors(async () => prepareHermesYaml([user], fsWith(), version));
      expect(user.data, version).toEqual({});
      expect(loadErrors[0]?.message, version).toMatch(/found duplicate key at line 4 — Hermes .* runs on its default settings/);
    }
  });

  it('older releases keep the last value', async () => {
    const user = yaml(raw);
    const { loadErrors } = await captureConfigLoadErrors(async () => prepareHermesYaml([user], fsWith(), '0.21.5'));
    expect(loadErrors).toEqual([]);
    expect(user.data).toEqual({ _config_version: 52, approvals: { mode: 'off' } });
  });

  it('a rejected managed file is ignored, not applied', async () => {
    const managed = yaml('approvals:\n  mode: manual\n  mode: manual\n', true);
    const { loadErrors } = await captureConfigLoadErrors(async () => prepareHermesYaml([managed], fsWith(), '0.21.6'));
    expect(managed.data).toEqual({});
    expect(loadErrors[0]?.message).toContain('ignores this administrator-managed config');
  });
});

describe('Hermes managed overlay (apply_managed_overlay + _deep_merge)', () => {
  it('promotes a bare managed model id to model.default: the user\'s provider and endpoint stay', () => {
    const user = yaml('model:\n  default: x/y\n  provider: custom\n  base_url: http://10.0.0.5:8000/v1\napprovals:\n  mode: "off"\n');
    const managed = yaml('approvals: null\nmodel: openrouter/anthropic/claude\n', true);
    const configs = [user, managed];
    prepareHermesYaml(configs, fsWith(), '0.20.0');
    expect(managed.data.model).toEqual({ default: 'openrouter/anthropic/claude' });
    expect(managedOverride(configs, user, 'model.base_url')).toBeUndefined();
    expect(managedOverride(configs, user, 'model.default')).toBe(managed);
    // `null` over a mapping is ignored
    expect(managedOverride(configs, user, 'approvals.mode')).toBeUndefined();
    expect(hermesDeepMerge(user.data, managed.data)).toMatchObject({
      model: { default: 'openrouter/anthropic/claude', provider: 'custom', base_url: 'http://10.0.0.5:8000/v1' },
      approvals: { mode: 'off' },
    });
    expect(hermesAdapter.getModels!(configs)).toEqual([{ id: 'openrouter/anthropic/claude', provider: 'custom' }]);
  });

  it('canonicalizes the managed model keys first (root provider/base_url, api_base, model.name)', () => {
    expect(hermesManagedOverlay({ model: 'a/b', provider: 'openrouter', base_url: 'https://x' }))
      .toEqual({ model: { default: 'a/b', provider: 'openrouter', base_url: 'https://x' } });
    expect(normalizeHermesModelKeys({ model: { name: 'm', api_base: 'http://h', provider: 2 } }))
      .toEqual({ model: { default: 'm', base_url: 'http://h', provider: '2' } });
    expect(normalizeHermesModelKeys({ model: { default: { model: 'n', provider: 'p' }, provider: 'auto' } }))
      .toEqual({ model: { default: 'n', provider: 'p' } });
    // Nothing to canonicalize: unchanged
    const plain = { model: { default: 'x' } };
    expect(normalizeHermesModelKeys(plain)).toBe(plain);
  });

  it('a managed value replaces a user scalar, and a managed null replaces a user scalar too', () => {
    const user = yaml('model: x/y\nterminal: docker\n');
    const managed = yaml('model:\n  provider: custom\nterminal: null\n', true);
    const configs = [user, managed];
    prepareHermesYaml(configs, fsWith(), '0.21.6');
    expect(hermesYamlSetting(configs, 'terminal')?.config).toBe(managed);
    expect(hermesYamlSetting(configs, 'model.provider')?.value).toBe('custom');
    expect(hermesDeepMerge(user.data, managed.data)).toEqual({ model: { provider: 'custom' }, terminal: null });
  });

  it('expands managed ${VAR} refs from the user .env (Hermes loads it into the environment first)', async () => {
    const user = yaml('approvals:\n  mode: manual\n');
    const managed = yaml('approvals:\n  mode: ${MODE}\n', true);
    const configs = [user, managed, env({ MODE: 'off' })];
    prepareHermesYaml(configs, fsWith(), '0.20.0');
    expect(managed.data).toEqual({ approvals: { mode: 'off' } });
    const hm008 = hermesChecks.find(c => c.id === 'HM-008')!;
    const ctx = { installation: { agent: 'hermes' as const, installDir: '/h/.hermes', configFiles: configs }, configs, platform: 'linux' as const, fs: fsWith() };
    const result = await hm008.run(ctx);
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });
});
