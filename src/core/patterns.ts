export const API_KEY_PATTERNS = [
  { pattern: /sk-[a-zA-Z0-9]{20,}/, name: 'OpenAI API key' },
  { pattern: /sk-ant-[a-zA-Z0-9-]{20,}/, name: 'Anthropic API key' },
  { pattern: /AKIA[0-9A-Z]{16}/, name: 'AWS Access Key' },
  { pattern: /ghp_[a-zA-Z0-9]{36}/, name: 'GitHub PAT' },
  { pattern: /gho_[a-zA-Z0-9]{36}/, name: 'GitHub OAuth token' },
  { pattern: /glpat-[a-zA-Z0-9\-_]{20,}/, name: 'GitLab PAT' },
  { pattern: /xoxb-[0-9]+-[0-9a-zA-Z]+/, name: 'Slack Bot token' },
  { pattern: /xoxp-[0-9]+-[0-9a-zA-Z]+/, name: 'Slack User token' },
  { pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/, name: 'Private key' },
  { pattern: /\b[0-9]{10}:[A-Za-z0-9_-]{35}\b/, name: 'Telegram Bot token' },
];

export const OAUTH_SECRET_PATTERNS = [
  { pattern: /^client_secret$/i, name: 'OAuth client secret (key name)' },
  { pattern: /^oauth[_-]?(?:client[_-]?)?secret$/i, name: 'OAuth secret (key name)' },
  { pattern: /^(?:access|refresh)[_-]?token$/i, name: 'OAuth token (key name)' },
  { pattern: /^oauth[_-]?(?:access|refresh)?[_-]?token$/i, name: 'OAuth token (key name)' },
  { pattern: /^authorization[_-]?code$/i, name: 'OAuth authorization code (key name)' },
];

export const OAUTH_TOKEN_VALUE_PATTERNS = [
  { pattern: /^ya29\.[a-zA-Z0-9_-]+/, name: 'Google OAuth access token' },
  { pattern: /^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/, name: 'JWT bearer token' },
  { pattern: /^ory_at_[a-zA-Z0-9_-]+/, name: 'Ory OAuth access token' },
];
