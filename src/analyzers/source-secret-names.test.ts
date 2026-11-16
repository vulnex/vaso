import { describe, it, expect } from 'vitest';
import { findSourceSecrets, isSecretKeyName } from './source-secrets.js';

const VALUE = 'Qx7rT2mLp9Vz4KsW8nBc3HdF6yJa';

describe('credential key names', () => {
  it.each([
    'secretKey', 'SECRET_KEY', 'client_secret_key', 'secret_key_base', 'signingKey', 'stripeKey', 'apiKeyV2', 'password2',
    'dbPass', 'privateKeyPem', 'authToken', 'jwtSecret', 'AWS_SECRET_ACCESS_KEY', 'X-Api-Key', 'apiKey', 'token', 'password',
    'clientsecret', 'encryption_key', 'webhookSigningSecret', 'licenseKey', 'my-service-api-key', 'ENCRYPTION_KEY', 'hmacKey',
    'DB_PASSWORD_2', 'apiSecretValue', 'tokenValue', 'SECRET_B64', 'passwordForAdmin', 'SESSION_SECRET', 'jwtVerifyKey',
  ])('%s holds a credential', (name) => {
    expect(isSecretKeyName(name)).toBe(true);
    expect(findSourceSecrets(`const config = { ${JSON.stringify(name)}: "${VALUE}" };`)).toHaveLength(1);
  });

  it.each([
    'secret_name', 'secretName', 'tokenPath', 'passwordFile', 'tokenUrl', 'passwordLength', 'tokenType', 'clientSecretId',
    'apiKeyHeader', 'API_KEY_ENV', 'secretArn', 'SECRET_REF', 'isSecret', 'hasPassword', 'TOKEN_KEY', 'TOKEN_STORAGE_KEY', 'publicKey',
    'cacheKey', 'sortKey', 'idempotencyKey', 'passwordHash', 'key', 'keys', 'tokenizer', 'bypass', 'passwordField', 'PROD_WRITE_KEY', 'APP_INSIGHTS_KEY',
    'secretKeyFormat2', 'sshKeyFingerprint', 'HOST_KEY_FINGERPRINT', 'posthogKey', 'featureFlagKey',
    'shardKey', 'deduplicationKey', 'assetKey', 'maxTokens', 'nextPageToken',
  ])('%s does not', (name) => {
    expect(isSecretKeyName(name)).toBe(false);
    expect(findSourceSecrets(`const config = { ${JSON.stringify(name)}: "${VALUE}" };`)).toEqual([]);
  });

  // Names that hold a credential only when the value is opaque key material
  it.each([
    'primaryKey', 'secondaryKey', 'COSMOS_SECONDARY_KEY', 'TENANT_KEY', 'MODEL_KEY', 'modelKey', 'SERVICEBUS_NAMESPACE_KEY', 'S3_KEY',
    'INPUT_TOKEN', 'contextToken', 'syncToken', 'AUTH_TOKEN_COOKIE', 'CSRF_TOKEN_COOKIE', 'ADMIN_PASSWORD_RULE', 'PASSWORD_RULE',
    'secretFlag', 'API_KEY_USAGE',
  ])('%s holding random key material is flagged', (name) => {
    expect(isSecretKeyName(name)).toBe(false);
    expect(findSourceSecrets(`const config = { ${JSON.stringify(name)}: "${VALUE}" };`)).toHaveLength(1);
    expect(findSourceSecrets(`const ${name} = "Zm9vYmFyYmF6cXV4UXdlcnR5MTIzNDU2Nzg5MEFCQ0Q=";`)).toHaveLength(1);
  });

  it.each([
    ['primaryKey', 'user_id_2024_v2'],
    ['secondaryKey', 'created_at_desc_2'],
    ['TENANT_KEY', 'acme-corp-eu-west-1'],
    ['modelKey', 'claude-3-5-sonnet-20241022'],
    ['S3_KEY', 'exports/2024-11/report-9f8e7d.csv'],
    ['S3_KEY', 'data/2024/file123abc'],
    ['contextToken', 'ctx-2024-session-9f8e7d6c'],
    ['syncToken', 'sync_2024_11_16_9f8e7d'],
    ['AUTH_TOKEN_COOKIE', '__Host-auth-token-2024'],
    ['secretFlag', 'ENABLE_SECRET_SCAN_V2'],
  ])('%s holding a name or path (%s) is not flagged', (name, value) => {
    expect(findSourceSecrets(`const ${name} = "${value}";`)).toEqual([]);
  });

  it.each(['TOKEN_STRINGS', 'TOKEN_CHARS', 'PASSWORD_ALPHABET', 'SECRET_CHARSET', 'apiKeyCharacters', 'TOKEN_DELIMITERS'])(
    '%s holding a shuffled character set (every character once) is not flagged',
    (name) => {
      expect(isSecretKeyName(name)).toBe(false);
      expect(findSourceSecrets(`const config = { ${JSON.stringify(name)}: "${VALUE}" };`)).toEqual([]);
    },
  );

  it('TOKEN_CHARS holding random key material (characters repeat) is flagged', () => {
    expect(findSourceSecrets('const TOKEN_CHARS = "Qx7rT2mLp9Vz4KsW8nBc3HdF6yJaQx7rT2mL";')).toHaveLength(1);
  });

  it('an environment lookup default under a credential name is found', () => {
    expect(findSourceSecrets(`SECRET_KEY = os.getenv("SECRET_KEY", "${VALUE}")`).length).toBeGreaterThan(0);
    expect(findSourceSecrets(`DB = os.environ.get("DB_NAME", "${VALUE}")`)).toEqual([]);
  });
});

describe('values that describe a credential rather than hold one', () => {
  it.each([
    ['TOKEN_STRINGS', '[A-Za-z0-9._~+/-]+=*'],
    ['TOKEN_CHARS', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'],
    ['PASSWORD_ALPHABET', 'abcdefghjkmnpqrstuvwxyz23456789'],
    ['SECRET_CHARSET', '0123456789abcdefABCDEF-_'],
    ['apiKeyCharacters', '0123456789ABCDEFGHJKMNPQRSTVWXYZ'],
    ['TOKEN_DELIMITERS', ',;:|0123456789abcXYZ'],
    ['secretKeyFormat2', 'sk_[a-z]{4}_[0-9A-Za-z]{24}'],
    ['PASSWORD_RULE', '^(?=.*[A-Z])(?=.*\\\\d).{12,}$'],
    ['sshKeyFingerprint', 'SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8'],
    ['jwtVerifyKey', 'MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE'],
    ['rsaVerifyKey', 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0'],
    ['posthogKey', 'phc_Zx81mQe4Lr0wVh7Tn2Kp9sDf6GjB3cYa5uXo1iNq8tW'],
    ['modelKey', 'claude-3-5-sonnet-20241022'],
    ['assetKey', 'main.8f3a2b91c4d7e6f0.js'],
    ['CSRF_TOKEN_COOKIE', '__Host-csrf-token-v2-2024'],
  ])('%s is not flagged', (name, value) => {
    expect(findSourceSecrets(`var ${name} = "${value}";`)).toEqual([]);
  });

  it.each([
    ['adminPassword', 'Zx9[Qm4]+Lp2Rt8Vw3Yb7Kc'],
    ['adminPassword', 'Kq7\\\\dPz2Lm9Xw4Rt6Yh'],
    ['dbPassword', 'Hy7Nq{12}Wz3Lp8Kd5'],
    ['apiSecret', 'sha256:Qx7rT2mLp9Vz4KsW8nBc3HdF6yJa1b2C3d4E5f'],
    ['clientSecret', 'SHA256:Qx7rT2mLp9Vz4KsW8nBc3HdF6yJa1b2C3d4E5f'],
  ])('%s holding a password with one regex-like character (%s) is flagged', (name, value) => {
    expect(findSourceSecrets(`const ${name} = "${value}";`)).toHaveLength(1);
  });

  it.each([
    ['hostKey', 'SHA256:Qx7rT2mLp9Vz4KsW8nBc3HdF6yJa1b2C3d4E5f6g7h8'],
    ['apiSecret', '^[A-Za-z0-9]{32}$'],
    ['secretValue', '(sk|pk)_(live|test)_[0-9a-zA-Z]{24}'],
  ])('%s holding a fingerprint or a regex (%s) is not flagged', (name, value) => {
    expect(findSourceSecrets(`const ${name} = "${value}";`)).toEqual([]);
  });

  it('the hono bearer-auth token pattern is not a credential', () => {
    expect(findSourceSecrets('var TOKEN_STRINGS = "[A-Za-z0-9._~+/-]+=*";')).toEqual([]);
  });

  it.each([
    ['SECRET_KEY', 'django-insecure-8f3a2b91c4d7e6f09a1b2c3d'],
    ['secretKey', 'q8Zr2xLm7Vt4Nc9Bw1Ks6Hd3Fg5Jp0Ya'],
    ['client_secret_key', 'x7Q9mZr2LcV8nT4kP1wJ6hD5'],
    ['secret_key_base', 'Zx81mQe4Lr0wVh7Tn2Kp9sDf6GjB3cYa'],
    ['stripeKey', 'Qz7xHunter9Kettle2Lamp5ab'],
    ['apiKeyV2', 'Qz7xHunter9Kettle2Lamp5ab'],
    ['password2', 'Qz7xHunter9Kettle2Lamp5'],
    ['dbPass', 'Qz7xHunter9Kettle2Lamp5'],
    ['jwtVerifyKey', 'Zx81mQe4Lr0wVh7Tn2Kp9sDf6GjB3cYa'],
    ['privateKeyPem', 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7'],
    ['licenseKey', 'LK-8F3A2B91-C4D7E6F0-9A1B2C3D'],
  ])('%s holding key material is still flagged', (name, value) => {
    expect(findSourceSecrets(`const ${name} = "${value}";`)).toHaveLength(1);
  });
});
