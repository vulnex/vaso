const crypto = require('crypto');
const https = require('https');

// MCP-011: All OAuth endpoints use HTTPS
const OAUTH_CONFIG = {
  authorization_endpoint: 'https://auth.example.com/authorize',
  token_endpoint: 'https://auth.example.com/oauth/token',
  discovery: 'https://auth.example.com/.well-known/oauth-authorization-server',
};

// MCP-013: PKCE implementation with S256
function generatePKCE() {
  const code_verifier = crypto.randomBytes(32).toString('base64url');
  const code_challenge = crypto
    .createHash('sha256')
    .update(code_verifier)
    .digest('base64url');
  return { code_verifier, code_challenge, code_challenge_method: 'S256' };
}

// MCP-013 + MCP-018: OAuth flow with PKCE and state
function startOAuthFlow() {
  const pkce = generatePKCE();
  const state = crypto.randomUUID();

  const params = new URLSearchParams({
    client_id: process.env.CLIENT_ID,
    redirect_uri: 'https://myapp.example.com/oauth/callback',
    response_type: 'code',
    scope: 'read:data write:own',
    code_challenge: pkce.code_challenge,
    code_challenge_method: pkce.code_challenge_method,
    state: state,
  });

  // Store state and verifier securely for later validation
  storeSession({ state, code_verifier: pkce.code_verifier });

  return `${OAUTH_CONFIG.authorization_endpoint}?${params.toString()}`;
}

// MCP-013: Token exchange with code_verifier
function exchangeToken(code, session) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: code,
    code_verifier: session.code_verifier,
    client_id: process.env.CLIENT_ID,
    redirect_uri: 'https://myapp.example.com/oauth/callback',
  });

  return fetch(OAUTH_CONFIG.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
}

// MCP-014: Secure token handling — no logging, no localStorage, no query params
function handleTokenResponse(response) {
  const token = response.access_token;
  // Store encrypted, not in localStorage or logs
  return encryptAndStore(token);
}

function encryptAndStore(token) {
  const key = crypto.scryptSync(process.env.ENCRYPTION_KEY, 'salt', 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = cipher.update(token, 'utf8', 'hex') + cipher.final('hex');
  return { encrypted, iv: iv.toString('hex'), tag: cipher.getAuthTag().toString('hex') };
}

// MCP-015: No token passthrough — uses own service credentials for downstream
function callDownstreamAPI(data) {
  const serviceToken = process.env.DOWNSTREAM_SERVICE_TOKEN;
  return fetch('https://downstream-api.example.com/data', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${serviceToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
  });
}

// MCP-016: HTTPS redirect URI only
const REDIRECT_CONFIG = {
  redirect_uri: 'https://myapp.example.com/oauth/callback',
};

// MCP-017: Minimal scopes — only what's needed
function getRequiredScopes() {
  return 'read:data write:own';
}

// MCP-018: Callback handler that verifies state
function handleOAuthCallback(req, session) {
  const { code, state } = req.query;

  // Verify state matches to prevent CSRF
  if (state !== session.state) {
    throw new Error('Invalid state parameter — possible CSRF attack');
  }

  return exchangeToken(code, session);
}

function storeSession(data) {
  // Secure server-side session storage
}

module.exports = { startOAuthFlow, exchangeToken, handleTokenResponse, handleOAuthCallback };
