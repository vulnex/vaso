import { describe, it, expect } from 'vitest';
import type { MCPServerSource, ScanContext } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { mcp013 } from './mcp-013-missing-pkce.js';
import { mcp018 } from './mcp-018-missing-state-parameter.js';

const ctx = (sourceCode: string, language?: 'python'): ScanContext => ({
  installation: { agent: 'mcp', installDir: '/x', configFiles: [] },
  configs: [], platform: 'darwin', fs: new LocalFSProvider(),
  mcpServerSources: [{ serverName: 's', localPath: '/x/s', sourceCode, ...(language ? { language } : {}) } as MCPServerSource],
});

const filler = (n: number) => Array.from({ length: n }, (_, i) => `    const pad${i} = ${i};`).join('\n');

describe('MCP-013 / MCP-018 judge the flow, not a 15-line window (dt14)', () => {
  it('passes PKCE and state set further down the same function (GitLab proxy shape)', async () => {
    const code = [
      'async function authorize(client, params, res) {',
      '    const targetUrl = new URL(`${base}/oauth/authorize`);',
      filler(50),
      '    targetUrl.searchParams.set("code_challenge", challenge);',
      '    targetUrl.searchParams.set("code_challenge_method", "S256");',
      '    targetUrl.searchParams.set("state", params.state);',
      '    res.redirect(targetUrl.toString());',
      '}',
    ].join('\n');
    expect((await mcp013.run(ctx(code))).passed).toBe(true);
    expect((await mcp018.run(ctx(code))).passed).toBe(true);
  });

  it('ignores a string constant naming the endpoint (Hostinger shape)', async () => {
    const code = 'const AUTHORIZE_PATH = "/api/external/v1/oauth-server/authorize";\n' + filler(150);
    expect((await mcp013.run(ctx(code))).passed).toBe(true);
    expect((await mcp018.run(ctx(code))).passed).toBe(true);
  });

  it('accepts a callback route that hands the whole callback URL to a verifying handler (workspace-mcp)', async () => {
    const code = [
      'from auth.google_auth import handle_auth_callback',
      'class S:',
      '    def setup(self):',
      '        @self.app.get("/oauth2callback")',
      '        async def oauth_callback(request):',
      '            code = request.query_params.get("code")',
      '            user, creds = await handle_auth_callback(',
      '                scopes=get_current_scopes(),',
      '                authorization_response=str(request.url),',
      '            )',
    ].join('\n');
    expect((await mcp018.run(ctx(code, 'python'))).passed).toBe(true);
  });

  it('still flags an authorize URL with neither PKCE nor state, and a callback that never checks state', async () => {
    const noPkce = 'function start() {\n  const u = new URL(`${base}/oauth/authorize?client_id=${id}&response_type=code`);\n  res.redirect(u.toString());\n}\n';
    expect((await mcp013.run(ctx(noPkce))).passed).toBe(false);
    expect((await mcp018.run(ctx(noPkce))).passed).toBe(false);
    const cb = "app.get('/oauth/callback', async (req, res) => {\n  const code = req.query.code;\n  const tok = await exchange({ grant_type: 'authorization_code', code });\n  res.send(tok);\n});\n";
    expect((await mcp018.run(ctx(cb))).passed).toBe(false);
  });
});
