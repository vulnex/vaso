import { describe, it, expect } from 'vitest';
import { isKnownSecretValue, isSecretNamedValue, looksRandom } from './secret-values.js';

// dt20 g6-F1/F2: GEM-001/QC-001/CC-004 value judgement (fixtures g6/fx-keys, fx-keys2)
describe('isSecretNamedValue', () => {
  it.each([
    ['GITLAB_TOKEN', 'glpat-Ab3De5Fg7Hj9Kl1Mn3Pq'],
    ['AWS_ACCESS_KEY', 'AKIAZ7Q3LMN4OPQ5RST6'],
    ['OPENWEATHER_API_KEY', '3f9a1c7e2b8d4f6a0c5e9b1d7f3a8c2e'],
    ['SERVICE_TOKEN', '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b'],
    ['LANGFUSE_SECRET_KEY', 'sk-lf-1c2d3e4f-5a6b-7c8d-9e0f-a1b2c3d4e5f6'],
    ['HEROKU_API_KEY', '1c2d3e4f-5a6b-7c8d-9e0f-a1b2c3d4e5f6'],
    ['MISTRAL_KEY', 'Zq8xL2vN7pR4tW9yB3dF6hJ1kM5nQ0sU'],
    ['HF_TOKEN', 'hf_Ab3De5Fg7Hj9Kl1Mn3Pq5R'],
    ['XAI_API_KEY', 'xai-Ab3De5Fg7Hj9Kl1Mn3Pq5Rs7Tu9Vw1XyZaBcDeFgHiJkLmNoPq'],
    ['AWS_SECRET_ACCESS_KEY', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYzQ9kL2mN4p'],
    ['DB_PASSWORD', 'Pq7Wz2Lk9Xv4Rt8Ns3Jm'],
  ])('%s=%s is a secret', (name, value) => {
    expect(isSecretNamedValue(name, value)).toBe(true);
  });

  it.each([
    ['SSH_PUBLIC_KEY', 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq8vJ3kLm9Pq2Rs5Tv8Wy1Ab4Cd6Ef0GhJkLmNoPqRs alice@laptop'],
    ['DEPLOY_KEY', 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7q8vJ3kLm9Pq2Rs5Tv8Wy1Ab4Cd6Ef0GhJkLmNoPqRs'],
    ['OAUTH_CLIENT_ID', '123456789012-a1b2c3d4e5f6g7h8i9j0klmnopqrstuv.apps.googleusercontent.com'],
    ['GOOGLE_OAUTH_CLIENT', '123456789012-a1b2c3d4e5f6g7h8i9j0klmnopqrstuv.apps.googleusercontent.com'],
    ['TOKEN_SECRET_ARN', 'arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/gemini-AbCdEf'],
    ['DB_SECRET', 'arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf'],
    ['VAULT_TOKEN', 'op://Private/Gemini Production/credential-field-2'],
    ['AUTH_URL', 'https://accounts.google.com/o/oauth2/v2/auth?prompt=consent&scope=openid'],
    ['API_KEY_FILE', '~/.config/secrets/gemini-production-api.key'],
    ['PRIMARY_KEY', 'user_id_and_created_at_timestamp_desc'],
    ['SESSION_KEY_PREFIX', 'gemini-session-cache-v2'],
    ['STRIPE_PUBLISHABLE_KEY', 'pk_live_51H8xL2vN7pR4tW9yB3dF6hJ1kM5nQ0sU'],
    ['LANGFUSE_PUBLIC_KEY', 'pk-lf-1c2d3e4f-5a6b-7c8d-9e0f-a1b2c3d4e5f6'],
    ['AZURE_TENANT_ID', '1c2d3e4f-5a6b-7c8d-9e0f-a1b2c3d4e5f6'],
    ['GITHUB_TOKEN', '${GITHUB_TOKEN}'],
    ['API_KEY', 'your-api-key-here-0123456789'],
    ['MAX_TOKENS', '4096'],
    ['AUTH_TYPE', 'oauth2-personal'],
    ['ADMIN_PASSWORD', '$2b$12$KIXQJ3wq0y8sYlE2zFh6UeZq8xL2vN7pR4tW9yB3dF6hJ1kM5n'],
    ['PASSWORD_HASH', 'Zq8xL2vN7pR4tW9yB3dF6hJ1kM5nQ0sU'],
  ])('%s=%s is not a secret', (name, value) => {
    expect(isSecretNamedValue(name, value)).toBe(false);
  });
});

describe('isKnownSecretValue', () => {
  it('recognises formats under any name, and secret URLs', () => {
    expect(isKnownSecretValue('glpat-Ab3De5Fg7Hj9Kl1Mn3Pq')).toBe(true);
    expect(isKnownSecretValue('github_pat_11ABCDEFG0abcdefghijkl_MNOPQRSTUVWXYZabcdefghij')).toBe(true);
    expect(isKnownSecretValue('https://hooks.slack.com/services/T01ABCDEF/B02GHIJKL/Zq8xL2vN7pR4tW9yB3dF6hJ1')).toBe(true);
    // random but nameless: not judged without a credential name
    expect(isKnownSecretValue('Zq8xL2vN7pR4tW9yB3dF6hJ1kM5nQ0sU')).toBe(false);
    expect(isKnownSecretValue('https://example.com/docs')).toBe(false);
  });
});

describe('looksRandom', () => {
  it('scales the entropy bar with the length (a 20-char key cannot reach 4.5 bits)', () => {
    expect(looksRandom('Pq7Wz2Lk9Xv4Rt8Ns3Jm')).toBe(true);
    expect(looksRandom('a8f3k2m9q4z7x1c5v6b0')).toBe(true);
    expect(looksRandom('Production2024')).toBe(false); // under 16
    expect(looksRandom('max_tokens=4096x', 12)).toBe(false);
    expect(looksRandom('aaaaaaaaaaaaaaaaaaaaaaaa1')).toBe(false);
    expect(looksRandom('Pq7Wz2Lk 9Xv4Rt8Ns3Jm')).toBe(false);
  });
});
