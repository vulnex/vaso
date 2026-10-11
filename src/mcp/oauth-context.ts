/**
 * Context tests shared by the OAuth source checks (MCP-013, MCP-018), so a
 * pattern that means "the server builds an authorization request" isn't
 * confused with code that merely mentions `/authorize` or a `state` field.
 */

/**
 * `/authorize` matched as a route the server *handles* (an authorization-server
 * proxy: `url.pathname === "/oauth/authorize"`, `app.get('/authorize', …)`),
 * not an authorization URL the server builds. PKCE/state for such a route are
 * the client's parameters, forwarded as-is.
 */
export const AUTHORIZE_ROUTE =
  /(?:pathname|path|url|route|endpoint)\s*(?:===?|!==?)\s*["'`][^"'`]*\/authoriz|\.(?:get|post|all|use|route|handle)\s*\(\s*["'`][^"'`]*\/authoriz|\bcase\s+["'`][^"'`]*\/authoriz/i;

/**
 * Parameters that make a nearby `state` an OAuth authorization-request state
 * rather than a parser/queue/UI state (`state: "successful-parse"`).
 */
export const OAUTH_REQUEST_CONTEXT = /\b(?:client_id|response_type|redirect_uri|code_challenge)\b|\/authoriz/;
