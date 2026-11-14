import { describe, it, expect } from 'vitest';
import { configHoldsSecret, isSecretLikeValue } from './secret-values.js';

describe('configHoldsSecret', () => {
  it('is false for ordinary settings', () => {
    expect(configHoldsSecret({})).toBe(false);
    expect(configHoldsSecret({ ui: { theme: 'GitHub' }, model: { name: 'gemini-2.5-pro' }, permissions: { allow: ['Bash(npm test)'] } })).toBe(false);
    expect(configHoldsSecret({ env: { OPENAI_API_KEY: '${OPENAI_API_KEY}', TOKEN: 'your-token-here' } })).toBe(false);
  });

  it('finds keys by format or by a secret key name with a random value', () => {
    expect(configHoldsSecret({ env: { ANTHROPIC_API_KEY: 'sk-ant-api03-Ab3dEf6hIj9kLm2nOp5qRs8tUv' } })).toBe(true);
    expect(configHoldsSecret({ mcpServers: { x: { headers: { Authorization: 'Bearer q8Z2vK4mN7pR1sT5wX9yB3cF6hJ0' } } } })).toBe(true);
    expect(isSecretLikeValue('q8Z2vK4mN7pR1sT5wX9yB3cF6hJ0', 'description')).toBe(false);
  });

  it('walks a config nested far deeper than the call stack allows', () => {
    const depth = 200_000;
    const deep = JSON.parse(`{"a":${'['.repeat(depth)}${']'.repeat(depth)}}`) as unknown;
    expect(configHoldsSecret(deep)).toBe(false);
    // a key early in document order is still found
    expect(configHoldsSecret({ env: { ANTHROPIC_API_KEY: 'sk-ant-api03-Ab3dEf6hIj9kLm2nOp5qRs8tUv' }, a: deep })).toBe(true);
  });
});
