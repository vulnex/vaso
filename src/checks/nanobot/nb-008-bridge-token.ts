import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { asRecord, getPath, isLoopbackHost, nanobotConfigs, nonEmptyString, pick, pyBool } from './shared.js';

/*
 * The websocket channel is nanobot's WebUI/client bridge and is always on
 * (channels/websocket/manifest.py: default_enabled, always_enabled). Defaults:
 * host 127.0.0.1, port 8765, websocketRequiresToken true, allowFrom ["*"].
 * Handshake auth (webui/gateway_endpoint.py): a static `token`, else an issued
 * short-lived token when websocketRequiresToken is true, else nothing. Tokens
 * are issued by tokenIssuePath, protected by tokenIssueSecret (or token).
 * No Origin check — any web page can open ws://127.0.0.1:8765.
 * The schema only rejects an unauthenticated 0.0.0.0 / :: bind; a specific
 * LAN address without auth loads fine.
 */

export const nb008 = defineCheck({
  id: 'NB-008',
  name: 'WebSocket / WebUI Channel Without Authentication',
  category: 'nanobot',
  severity: 'critical',
  description: 'Check the always-on websocket channel (WebUI and client bridge): websocketRequiresToken false with no static token, or a token-issue endpoint with no tokenIssueSecret, lets anyone who can reach the socket drive the agent — critical on a non-loopback bind, warning on loopback (no Origin check, so any web page in the user\'s browser can connect). Also flags plaintext ws:// on non-loopback binds and tools.webuiAllowRemotePackageInstall.',
  supportedAgents: ['nanobot'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let critical = false;

    for (const config of nanobotConfigs(ctx.configs)) {
      const ws = asRecord(getPath(config.data, 'channels.websocket')) ?? {};
      if (pyBool(ws.enabled) !== false) {
        const unixSocket = nonEmptyString(pick(ws, 'unixSocketPath'));
        const hostRaw = pick(ws, 'host');
        const host = nonEmptyString(hostRaw) ? hostRaw.trim() : '127.0.0.1';
        const local = unixSocket || isLoopbackHost(host);
        const token = nonEmptyString(pick(ws, 'token'));
        const issueSecret = nonEmptyString(pick(ws, 'tokenIssueSecret'));
        const issuePath = nonEmptyString(pick(ws, 'tokenIssuePath'));
        const proxyAuth = asRecord(pick(ws, 'trustedProxyAuth')) !== undefined;
        const requiresToken = pyBool(pick(ws, 'websocketRequiresToken')) !== false;
        const where = unixSocket ? 'a unix socket' : `${host}:${typeof ws.port === 'number' ? ws.port : 8765}`;

        let hole: string | undefined;
        if (!token && !requiresToken && !proxyAuth) {
          hole = 'websocketRequiresToken is false and no static token is set — connections are unauthenticated';
        } else if (!token && !issueSecret && issuePath && !proxyAuth) {
          hole = `tokenIssuePath ${JSON.stringify(pick(ws, 'tokenIssuePath'))} has no tokenIssueSecret — anyone can mint connection tokens`;
        }

        if (hole && unixSocket) {
          // unixSocketPath replaces the TCP listener and the socket is
          // chmod 0600 (runtime.py runner): browsers can't reach it and
          // other users can't open it
          evidence.push({
            file: config.filePath,
            snippet: `channels.websocket on ${where}`,
            detail: `${hole}; served only on unix socket ${String(pick(ws, 'unixSocketPath')).trim()} (mode 0600), which web pages and other users cannot open`,
            mitigated: true,
          });
        } else if (hole) {
          if (!local) critical = true;
          evidence.push({
            file: config.filePath,
            snippet: `channels.websocket on ${where}`,
            detail: local
              ? `${hole}; bound to loopback, but without an Origin check any web page the user opens can connect and drive the agent`
              : `${hole}; bound to ${host}, reachable from the network`,
          });
        } else if (!local && !(nonEmptyString(pick(ws, 'sslCertfile')) && nonEmptyString(pick(ws, 'sslKeyfile'))) && !proxyAuth) {
          evidence.push({
            file: config.filePath,
            snippet: `channels.websocket on ${where}`,
            detail: `WebSocket channel bound to ${host} without sslCertfile + sslKeyfile — connection tokens travel over plaintext ws://`,
          });
        }
      }

      if (pyBool(getPath(config.data, 'tools.webuiAllowRemotePackageInstall')) === true) {
        evidence.push({
          file: config.filePath,
          snippet: 'tools.webuiAllowRemotePackageInstall: true',
          detail: 'Non-local WebUI clients may install packages and agent skills on this host',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'WebSocket/WebUI channel requires authentication',
      failed: (n) => `${n} WebSocket/WebUI exposure issue(s)`,
      severity: evidence.length > 0 && !critical ? 'warning' : undefined,
      fixDescription: 'Keep channels.websocket.websocketRequiresToken true (default) and set tokenIssueSecret (`nanobot onboard` generates one) or a static token; bind host to 127.0.0.1 unless remote access is required, and then set sslCertfile/sslKeyfile; leave tools.webuiAllowRemotePackageInstall false',
    });
  },
});
