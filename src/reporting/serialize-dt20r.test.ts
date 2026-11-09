import { describe, expect, it } from 'vitest';
import { maskCredentialsInLine } from './serialize.js';

describe('maskCredentialsInLine — dt20 re-verify', () => {
  it('masks GitHub fine-grained PATs and app tokens in free text', () => {
    const pat = `github_pat_11ABCDEFG0${'x7Kq9Lm2Np'.repeat(6)}`;
    const out = maskCredentialsInLine(`Allow ${pat} use`);
    expect(out).not.toContain(pat.slice(0, 16));
    expect(out).not.toContain(pat.slice(-12));
    expect(maskCredentialsInLine(`ghs_${'Ab3dE5gH7j'.repeat(4)}`)).not.toContain('Ab3dE5gH7j');
  });

  it('masks a token a snippet cut off', () => {
    const cut = `Allow the deploy script that authenticates with ghp_C3J27XDCG2LmlZGEONYlgCtjfIZ4`;
    expect(maskCredentialsInLine(cut)).toBe('Allow the deploy script that authenticates with ghp_***');
    expect(maskCredentialsInLine(`key AKIAQUO6SBEGZ ...`)).toBe('key AKIA*** ...');
    expect(maskCredentialsInLine(`see the sk-ant-docs`)).toBe('see the sk-***');
  });

  it('keeps switches and token-window settings readable', () => {
    const line = '{"tokenTtlS":300,"websocketRequiresToken":true,"contextWindowTokens":200000}';
    expect(maskCredentialsInLine(line)).toBe(line);
  });
});

describe('maskCredentialsInLine — escaped JSON (dt20 re-verify 5)', () => {
  it('masks a credential pair written with backslash-escaped quotes', () => {
    const out = maskCredentialsInLine('Server "escaped": sh -c run --cfg "{\\"apiKey\\":\\"Rt5Yu6Io7Pa8Sd9Fg0Hj1Kl2\\"}"');
    expect(out).not.toContain('Rt5Yu6Io7Pa8');
    expect(out).toContain('\\"apiKey\\":\\"***\\"');
    const deeper = maskCredentialsInLine('{"c1":"curl -d \\"{\\\\\\"api_key\\\\\\":\\\\\\"Zr5DBLESC9wXyZ12\\\\\\"}\\""}');
    expect(deeper).not.toContain('Zr5DBLESC9');
    const keep = '{\\"region\\":\\"eu-west-1-abcdef\\"}';
    expect(maskCredentialsInLine(keep)).toBe(keep);
  });
});
