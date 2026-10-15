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

/**
 * An authorization endpoint URL in code: `/authorize` or `/authorization` as a
 * path segment that ends where a URL ends — a quote, `?`, `#` or `${…}`
 * (`\`${base}/oauth/authorize?${params}\``, `new URL("/authorize", issuer)`).
 * Not prose ("federation/authorization code", "authenticated/authorized"),
 * module paths (`handlers/authorize.js`, `headers/authorization.js`) or other
 * endpoints (`/oauth/authorize_device`).
 */
export const AUTHORIZE_URL = /\/(?:authorize|authorization)(?=["'`?#]|\$\{)/;

/**
 * The URL is assigned to a metadata/config key (`authorization_endpoint:`,
 * `"authorizationEndpoint":`, `authorizationUrl =`) without a query being
 * built on it: it describes where the endpoint is, it is not a request.
 */
const ENDPOINT_METADATA = /\b(?:authorization_?endpoint|authorization_?url|authorize_?url|auth_?url)["']?\s*[:=]/i;
const BUILDS_QUERY = /\/(?:authorize|authorization)\?|URLSearchParams|searchParams|\.search\b|[?&](?:client_id|response_type)=/;

export function isAuthorizeRequest(line: string): boolean {
  if (!AUTHORIZE_URL.test(line) || AUTHORIZE_ROUTE.test(line)) return false;
  return !(ENDPOINT_METADATA.test(line) && !BUILDS_QUERY.test(line));
}

/**
 * A token request with the authorization_code grant: `grant_type:
 * "authorization_code"`, `grant_type=authorization_code`, `.set("grant_type",
 * "authorization_code")`. Not a client registration's `grant_types` list.
 */
export const AUTH_CODE_GRANT = /\bgrant_type\b["']?\s*[:=,]\s*["'`]?authorization_code\b/;
