import { defineCheck } from '../../core/check-builder.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import type { ScanContext } from '../../core/types.js';
import { exposed, gatewayEnv, gatewayToml, record, gateway, settingEvidence } from './shared.js';
import { configFixTargets } from '../../remediation/fix-refusal.js';

function envSet(ctx: ScanContext, key: string): string | undefined {
  const v = gatewayEnv(ctx)?.data[key];
  return typeof v === 'string' && v.trim() ? v.trim() : undefined;
}

/**
 * A gateway TOML that gives TLS a certificate but no way to authenticate
 * callers: no client CA (or mTLS user auth turned off), no OIDC issuer and no
 * gateway JWT signing key. openshell-gateway 0.0.116 starts such a gateway
 * and logs "Neither mTLS user auth nor OIDC nor sandbox JWT auth is
 * configured — the gateway has no authentication mechanism". Judged only
 * when the TOML sets the TLS paths itself: a gateway on the generated TLS
 * directory (OPENSHELL_LOCAL_TLS_DIR) has its client CA there.
 *
 * OPENSHELL_LOCAL_TLS_DIR also turns on the gateway-minted sandbox JWT: its
 * jwt/ keys are generated there (`generate-certs`), and 0.0.116 then logs
 * "gateway-minted sandbox JWT enabled" and rejects calls without
 * credentials. The packaged launchers always set it — the deb user unit
 * (`Environment=OPENSHELL_LOCAL_TLS_DIR=%h/.local/state/openshell/tls`,
 * generate-certs as ExecStartPre) and the Homebrew wrapper — so only a
 * gateway.env that blanks it leaves the gateway without one.
 */
function noAuthMechanism(ctx: ScanContext): string | undefined {
  const gw = gateway(ctx);
  const tls = record(gw.tls);
  if (gw.disable_tls === true || envSet(ctx, 'OPENSHELL_DISABLE_TLS') === 'true') return undefined; // OSH-001
  if (typeof tls?.cert_path !== 'string' || !tls.cert_path.trim()) return undefined;
  const clientCa = (typeof tls.client_ca_path === 'string' && tls.client_ca_path.trim()) || envSet(ctx, 'OPENSHELL_TLS_CLIENT_CA');
  const mtlsOff = envSet(ctx, 'OPENSHELL_ENABLE_MTLS_AUTH') === 'false'
    || (envSet(ctx, 'OPENSHELL_ENABLE_MTLS_AUTH') === undefined && record(gw.mtls_auth)?.enabled === false);
  if (clientCa && !mtlsOff) return undefined;
  const oidc = record(gw.oidc);
  if ((typeof oidc?.issuer === 'string' && oidc.issuer.trim()) || envSet(ctx, 'OPENSHELL_OIDC_ISSUER')) return undefined;
  const jwt = record(gw.gateway_jwt);
  if (typeof jwt?.signing_key_path === 'string' && jwt.signing_key_path.trim()) return undefined;
  const envFile = gatewayEnv(ctx)?.data;
  const sandboxJwt = !envFile || !('OPENSHELL_LOCAL_TLS_DIR' in envFile) || envSet(ctx, 'OPENSHELL_LOCAL_TLS_DIR') !== undefined;
  if (sandboxJwt) return undefined;
  return clientCa
    ? 'mtls_auth.enabled = false, no OIDC issuer, OPENSHELL_LOCAL_TLS_DIR blank (no sandbox JWT)'
    : 'tls.cert_path set, no client_ca_path / OIDC issuer, OPENSHELL_LOCAL_TLS_DIR blank (no sandbox JWT)';
}

export const osh002 = defineCheck({
  id: 'OSH-002',
  name: 'OpenShell Gateway Accepts Unauthenticated Users',
  category: 'openshell',
  severity: 'critical',
  description: 'Detect `[openshell.gateway.auth] allow_unauthenticated_users = true`, or a TLS gateway with no client CA (mTLS), OIDC issuer or gateway JWT — the gateway accepts CLI/API calls without credentials, so anyone who reaches it manages every sandbox, policy and provider',
  supportedAgents: ['openshell'],

  fixTargets: configFixTargets,

  async run(ctx, h) {
    const remote = exposed(ctx);
    const toml = gatewayToml(ctx);
    if (record(gateway(ctx).auth)?.allow_unauthenticated_users === true) {
      return h.fromEvidence([settingEvidence(toml, 'allow_unauthenticated_users = true',
        remote
          ? `Gateway listens on ${ctx.installation.gateway?.host} — any host that reaches it is treated as a gateway user`
          : 'Any local process can manage sandboxes, policies and providers (documented as a local-development / trusted-proxy escape hatch)')], {
        passed: 'Gateway requires authenticated users',
        failed: () => 'OpenShell gateway accepts unauthenticated users',
        severity: remote ? 'critical' : 'warning',
        fixable: true,
        fixDescription: 'Set [openshell.gateway.auth] allow_unauthenticated_users = false and restart the gateway; use mTLS (local) or OIDC (shared gateways)',
      });
    }
    const none = noAuthMechanism(ctx);
    if (none) {
      return h.fromEvidence([settingEvidence(toml, none,
        'TLS is on, but no client CA (mTLS user auth), OIDC issuer or gateway JWT is configured, and gateway.env blanks OPENSHELL_LOCAL_TLS_DIR (no gateway-minted sandbox JWT) — the gateway logs "no authentication mechanism" and serves every caller'
        + (remote ? ` on ${ctx.installation.gateway?.host}` : ' (loopback listener: any local process)'))], {
        passed: 'Gateway requires authenticated users',
        failed: () => 'OpenShell gateway has no authentication mechanism',
        severity: remote ? 'critical' : 'warning',
        fixDescription: 'Configure [openshell.gateway.tls] client_ca_path (mTLS user auth, generated by `openshell-gateway generate-certs`) or an [openshell.gateway.oidc] issuer, and restart the gateway',
      });
    }
    return h.passed('Gateway requires authenticated users');
  },

  async fix(ctx) {
    const toml = gatewayToml(ctx);
    return fixFirstConfig(toml ? [toml] : [], {
      checkId: 'OSH-002',
      path: 'openshell.gateway.auth.allow_unauthenticated_users',
      value: false,
      message: 'Set allow_unauthenticated_users = false — restart the gateway to apply',
      noConfigMessage: 'No OpenShell gateway TOML found',
    });
  },
});
