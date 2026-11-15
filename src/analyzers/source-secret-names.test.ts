import { describe, it, expect } from 'vitest';
import { findSourceSecrets, isSecretKeyName } from './source-secrets.js';

const VALUE = 'Qx7rT2mLp9Vz4KsW8nBc3HdF6yJa';

describe('credential key names', () => {
  it.each([
    'secretKey', 'SECRET_KEY', 'client_secret_key', 'secret_key_base', 'signingKey', 'stripeKey', 'apiKeyV2', 'password2',
    'dbPass', 'privateKeyPem', 'authToken', 'jwtSecret', 'AWS_SECRET_ACCESS_KEY', 'X-Api-Key', 'apiKey', 'token', 'password',
    'clientsecret', 'encryption_key', 'webhookSigningSecret', 'licenseKey', 'my-service-api-key',
  ])('%s holds a credential', (name) => {
    expect(isSecretKeyName(name)).toBe(true);
    expect(findSourceSecrets(`const config = { ${JSON.stringify(name)}: "${VALUE}" };`)).toHaveLength(1);
  });

  it.each([
    'secret_name', 'secretName', 'tokenPath', 'passwordFile', 'tokenUrl', 'passwordLength', 'tokenType', 'clientSecretId',
    'apiKeyHeader', 'API_KEY_ENV', 'secretArn', 'SECRET_REF', 'isSecret', 'hasPassword', 'TOKEN_KEY', 'TOKEN_STORAGE_KEY', 'publicKey', 'primaryKey',
    'cacheKey', 'sortKey', 'idempotencyKey', 'passwordHash', 'key', 'keys', 'tokenizer', 'bypass', 'passwordField',
  ])('%s does not', (name) => {
    expect(isSecretKeyName(name)).toBe(false);
    expect(findSourceSecrets(`const config = { ${JSON.stringify(name)}: "${VALUE}" };`)).toEqual([]);
  });

  it('an environment lookup default under a credential name is found', () => {
    expect(findSourceSecrets(`SECRET_KEY = os.getenv("SECRET_KEY", "${VALUE}")`).length).toBeGreaterThan(0);
    expect(findSourceSecrets(`DB = os.environ.get("DB_NAME", "${VALUE}")`)).toEqual([]);
  });
});
