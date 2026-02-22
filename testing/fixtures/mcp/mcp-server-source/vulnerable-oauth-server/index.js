const http = require('http');
const fs = require('fs');
const querystring = require('querystring');

// MCP-011: HTTP OAuth endpoints (not HTTPS)
const OAUTH_CONFIG = {
  authorization_endpoint: 'http://auth.example.com/authorize',
  token_endpoint: 'http://auth.example.com/oauth/token',
};

// MCP-012: Hardcoded client secret (detected via config env, not source)
const CLIENT_SECRET = 'super-secret-client-value-abc123';

// MCP-013: OAuth flow without PKCE
function startOAuthFlow() {
  const authUrl = `http://auth.example.com/authorize?client_id=myapp&redirect_uri=http://myapp.com/callback&response_type=code&scope=*`;
  // No code_challenge parameter — PKCE missing
  return authUrl;
}

// MCP-013: Token exchange without code_verifier
function exchangeToken(code) {
  const body = querystring.stringify({
    grant_type: 'authorization_code',
    code: code,
    client_id: 'myapp',
    client_secret: CLIENT_SECRET,
  });
  // No code_verifier — PKCE not enforced on token exchange
  return fetch(OAUTH_CONFIG.token_endpoint, {
    method: 'POST',
    body: body,
  });
}

// MCP-014: Token logging
function handleTokenResponse(response) {
  const token = response.access_token;
  console.log('Received token: ' + token);

  // MCP-014: Token in localStorage
  localStorage.setItem('oauth_token', token);

  // MCP-014: Token in query parameter
  const apiUrl = '/api/data?access_token=' + token;
  return fetch(apiUrl);
}

// MCP-015: Token passthrough — forwarding inbound auth to outbound
function proxyRequest(req) {
  const authHeader = req.headers.authorization;
  return fetch('https://downstream-api.example.com/data', {
    headers: { authorization: req.headers.authorization },
  });
}

// MCP-016: HTTP redirect URI
const REDIRECT_CONFIG = {
  redirect_uri: 'http://myapp.example.com/oauth/callback',
};

// MCP-017: Wildcard/overly broad scope
function requestTokenWithBroadScope() {
  const params = {
    scope: '*',
    client_id: 'myapp',
  };
  return params;
}

// MCP-018: No state parameter in auth URL
function buildAuthUrl() {
  const url = 'https://auth.example.com/authorize?client_id=myapp&redirect_uri=https://myapp.com/callback&response_type=code';
  // No state parameter — vulnerable to CSRF
  return url;
}

// MCP-018: Static state value
function buildAuthUrlWithStaticState() {
  const params = {
    state: 'fixed-state-value',
    client_id: 'myapp',
    response_type: 'code',
  };
  return params;
}

// MCP-018: Callback handler that doesn't verify state
function handleOAuthCallback(req) {
  const code = req.query.code;
  // Does not verify state — grants authorization_code directly
  return exchangeToken(code);
}

module.exports = { startOAuthFlow, exchangeToken, handleTokenResponse, proxyRequest };
