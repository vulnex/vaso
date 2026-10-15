import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig, AgentInstallation, GatewayInfo } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { openshellChecks } from './index.js';

const HOME = '/home/test';
const CFG = `${HOME}/.config/openshell`;
const STATE = `${HOME}/.local/state/openshell`;
const TOML = `${CFG}/gateway.toml`;

interface FsOpts {
  files?: Record<string, string>;
  modes?: Record<string, number>;
  env?: Record<string, string>;
  dirs?: Record<string, { name: string; dir?: boolean }[]>;
  exec?: (args: string[]) => { exitCode: number; stdout: string };
}

function makeFs({ files = {}, modes = {}, env = {}, dirs = {}, exec }: FsOpts = {}): FSProvider {
  const exists = (p: string) => p in files || p in modes || p in dirs;
  return {
    platform: 'linux',
    homedir: () => HOME,
    getEnv: (k: string) => env[k],
    access: vi.fn(async (p: string) => exists(p)),
    readFile: vi.fn(async (p: string) => {
      if (!(p in files)) throw new Error(`ENOENT ${p}`);
      return files[p];
    }),
    stat: vi.fn(async (p: string) => {
      if (!(p in modes)) throw new Error(`ENOENT ${p}`);
      return { mode: modes[p], isFile: () => true, isDirectory: () => false };
    }),
    readdirEntries: vi.fn(async (d: string) => (dirs[d] ?? []).map(e => ({ name: e.name, isDirectory: !!e.dir, isFile: !e.dir }))),
    exec: vi.fn(async (_cmd: string, args: string[]) => ({ stderr: '', ...(exec?.(args) ?? { exitCode: 1, stdout: '' }) })),
  } as unknown as FSProvider;
}

function gatewayToml(gateway: Record<string, unknown>, extra: Record<string, unknown> = {}): ParsedConfig {
  return { raw: '', format: 'toml', filePath: TOML, data: { openshell: { version: 2, gateway, ...extra } } };
}

function ctx(configs: ParsedConfig[], fs: FSProvider = makeFs(), opts: { gateway?: GatewayInfo; cli?: string } = {}): ScanContext {
  const installation: AgentInstallation = {
    agent: 'openshell',
    installDir: CFG,
    configFiles: configs,
    gateway: opts.gateway ?? { host: '127.0.0.1', port: 17670, tls: true, authMode: 'mtls' },
    cliBinary: opts.cli,
  };
  return { installation, configs, platform: 'linux', fs };
}

const PUBLIC: GatewayInfo = { host: '0.0.0.0', port: 17670, tls: false, authMode: 'none' };
const check = (id: string) => openshellChecks.find(c => c.id === id)!;

/** A CLI that answers the read-only gateway queries with the given sandboxes and policies. */
function cliFs(list: unknown, policies: Record<string, unknown>, global?: unknown, extra: FsOpts = {}): FSProvider {
  return makeFs({
    ...extra,
    exec: (args) => {
      if (args[0] === 'sandbox' && args[1] === 'list') return { exitCode: 0, stdout: JSON.stringify(list) };
      if (args[0] === 'policy' && args[2] === '--global') {
        return global ? { exitCode: 0, stdout: JSON.stringify({ policy: global }) } : { exitCode: 1, stdout: '' };
      }
      if (args[0] === 'policy' && args[1] === 'get') {
        const p = policies[`${args[4]}/${args[2]}`];
        return p ? { exitCode: 0, stdout: JSON.stringify({ policy: p, status: 'effective' }) } : { exitCode: 1, stdout: '' };
      }
      return { exitCode: 1, stdout: '' };
    },
  });
}

describe('OpenShell checks', () => {
  it('exports 14 checks scoped to openshell', () => {
    expect(openshellChecks).toHaveLength(14);
    for (const c of openshellChecks) {
      expect(c.id).toMatch(/^OSH-0(0[1-9]|1[0-4])$/);
      expect(c.category).toBe('openshell');
      expect(c.supportedAgents).toEqual(['openshell']);
    }
  });

  it('passes every check on a default install', async () => {
    for (const c of openshellChecks) {
      const r = await c.run(ctx([gatewayToml({})]));
      expect(r.passed, c.id).toBe(true);
    }
  });
});

describe('gateway settings', () => {
  it('OSH-001 flags disable_tls — critical when the gateway is reachable from other hosts', async () => {
    const local = await check('OSH-001').run(ctx([gatewayToml({ disable_tls: true })]));
    expect(local.passed).toBe(false);
    expect(local.severity).toBe('warning');
    const remote = await check('OSH-001').run(ctx([gatewayToml({ disable_tls: true })], makeFs(), { gateway: PUBLIC }));
    expect(remote.severity).toBe('critical');
    const viaEnv = await check('OSH-001').run(ctx([{ raw: '', format: 'env', filePath: `${CFG}/gateway.env`, data: { OPENSHELL_DISABLE_TLS: 'true' } }]));
    expect(viaEnv.evidence?.[0].snippet).toBe('OPENSHELL_DISABLE_TLS=true');
    const upper = await check('OSH-001').run(ctx([{ raw: '', format: 'env', filePath: `${CFG}/gateway.env`, data: { OPENSHELL_DISABLE_TLS: 'TRUE' } }]));
    expect(upper.evidence?.[0].snippet).toBe('OPENSHELL_DISABLE_TLS=TRUE');
  });

  it('OSH-002 flags unauthenticated users and offers a fix', async () => {
    const r = await check('OSH-002').run(ctx([gatewayToml({ auth: { allow_unauthenticated_users: true } })], makeFs(), { gateway: PUBLIC }));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
    expect(r.fixable).toBe(true);
    expect((await check('OSH-002').run(ctx([gatewayToml({ auth: { allow_unauthenticated_users: false } })]))).passed).toBe(true);
  });

  it('OSH-003 flags insecure OIDC', async () => {
    const r = await check('OSH-003').run(ctx([gatewayToml({ oidc: { issuer: 'http://idp.example.com', dangerously_allow_insecure_http: true } })]));
    expect(r.evidence).toHaveLength(2);
    expect((await check('OSH-003').run(ctx([gatewayToml({ oidc: { issuer: 'https://idp.example.com' } })]))).passed).toBe(true);
  });

  it('OSH-004 flags ssh_session_ttl_secs = 0, and missing JWT TTLs only on shared gateways', async () => {
    const ssh = await check('OSH-004').run(ctx([gatewayToml({ ssh_session_ttl_secs: 0 })]));
    expect(ssh.evidence).toHaveLength(1);
    expect(ssh.fixable).toBe(true);
    expect((await check('OSH-004').run(ctx([gatewayToml({})]))).passed).toBe(true);
    const shared = await check('OSH-004').run(ctx([gatewayToml({})], makeFs(), { gateway: PUBLIC }));
    expect(shared.evidence?.[0].snippet).toBe('gateway_jwt.ttl_secs unset');
    expect((await check('OSH-004').run(ctx([gatewayToml({ gateway_jwt: { ttl_secs: 3600 } })], makeFs(), { gateway: PUBLIC }))).passed).toBe(true);
  });

  it('OSH-005 flags retain_last_valid', async () => {
    const r = await check('OSH-005').run(ctx([gatewayToml({ policy_validation_failure_mode: 'retain_last_valid' })]));
    expect(r.passed).toBe(false);
    expect(r.fixable).toBe(true);
    expect((await check('OSH-005').run(ctx([gatewayToml({ policy_validation_failure_mode: 'fail_closed' })]))).passed).toBe(true);
  });

  it('OSH-006 flags fail-open, dynamic and plaintext extension services, not post-commit observers', async () => {
    const r = await check('OSH-006').run(ctx([gatewayToml({
      interceptors: [
        { name: 'quota', grpc_endpoint: 'http://10.0.0.5:9000', failure_policy: 'fail_open' },
        { name: 'audit', grpc_endpoint: 'unix:///run/a.sock', failure_policy: 'fail_open', binding_policy: 'allowlist', bindings: [{ rpc: 'x', phases: ['post_commit'] }] },
        { name: 'local', grpc_endpoint: 'http://127.0.0.1:9000', failure_policy: 'fail_closed', binding_policy: 'exact' },
      ],
    }, { supervisor: { middleware: [{ name: 'guard', grpc_endpoint: 'https://mw:50051', allow_insecure_transport: true }] } })]));
    const snippets = r.evidence!.map(e => e.snippet);
    expect(snippets).toEqual([
      'interceptor "quota": failure_policy = "fail_open"',
      'interceptor "quota": binding_policy = "dynamic"',
      'interceptor "quota": http://10.0.0.5:9000',
      'supervisor middleware "guard": https://mw:50051 (allow_insecure_transport)',
    ]);
  });

  it('OSH-006 flags allow_insecure_transport on an interceptor', async () => {
    const r = await check('OSH-006').run(ctx([gatewayToml({
      interceptors: [{ name: 'gov', grpc_endpoint: 'http://127.0.0.1:18081', failure_policy: 'fail_closed', binding_policy: 'allowlist', allow_insecure_transport: true }],
    })]));
    expect(r.evidence?.map(e => e.snippet)).toEqual(['interceptor "gov": http://127.0.0.1:18081 (allow_insecure_transport)']);
  });

  it('OSH-007 flags disabled admission, critical with caller driver config', async () => {
    const warn = await check('OSH-007').run(ctx([gatewayToml({}, { drivers: { docker: { resource_admission: { enabled: false } } } })]));
    expect(warn.severity).toBe('warning');
    const crit = await check('OSH-007').run(ctx([gatewayToml({}, { drivers: { kubernetes: { allow_driver_config: true, resource_admission: { enabled: false } } } })]));
    expect(crit.severity).toBe('critical');
    expect((await check('OSH-007').run(ctx([gatewayToml({}, { drivers: { docker: { allow_driver_config: true } } })]))).passed).toBe(true);
  });
});

describe('files', () => {
  it('OSH-008 flags readable key material and sandbox tokens', async () => {
    const fs = makeFs({
      modes: {
        [`${STATE}/tls/ca.key`]: 0o100644,
        [`${STATE}/tls/jwt/signing.pem`]: 0o100600,
        [`${STATE}/gateway/credentials/key-encryption-key.bin`]: 0o100640,
        [`${STATE}/gateway/openshell.db`]: 0o100644,
        [`${STATE}/docker-sandbox-tokens/default/abc/sandbox.jwt`]: 0o100644,
        [`${CFG}/gateways/work/mtls/tls.key`]: 0o100600,
      },
      dirs: {
        [`${STATE}/docker-sandbox-tokens`]: [{ name: 'default', dir: true }],
        [`${STATE}/docker-sandbox-tokens/default`]: [{ name: 'abc', dir: true }],
        [`${STATE}/docker-sandbox-tokens/default/abc`]: [{ name: 'sandbox.jwt' }],
        [`${CFG}/gateways`]: [{ name: 'work', dir: true }],
      },
    });
    const r = await check('OSH-008').run(ctx([], fs));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
    expect(r.evidence!.map(e => e.file).sort()).toEqual([
      `${STATE}/docker-sandbox-tokens/default/abc/sandbox.jwt`,
      `${STATE}/gateway/credentials/key-encryption-key.bin`,
      `${STATE}/gateway/openshell.db`,
      `${STATE}/tls/ca.key`,
    ]);
  });

  it('OSH-008 follows OPENSHELL_LOCAL_TLS_DIR and OPENSHELL_DB_URL from gateway.env', async () => {
    const env: ParsedConfig = { raw: '', format: 'env', filePath: `${CFG}/gateway.env`, data: { OPENSHELL_LOCAL_TLS_DIR: '/srv/os/tls', OPENSHELL_DB_URL: 'sqlite:/srv/os/openshell.db' } };
    const fs = makeFs({ modes: { '/srv/os/tls/ca.key': 0o100604, '/srv/os/openshell.db': 0o100644 } });
    const r = await check('OSH-008').run(ctx([env], fs));
    expect(r.evidence!.map(e => e.file).sort()).toEqual(['/srv/os/openshell.db', '/srv/os/tls/ca.key']);
  });

  it('OSH-008 checks the server key named by OPENSHELL_TLS_KEY in gateway.env', async () => {
    const env: ParsedConfig = { raw: '', format: 'env', filePath: `${CFG}/gateway.env`, data: { OPENSHELL_TLS_KEY: '~/certs/gw.key' } };
    const r = await check('OSH-008').run(ctx([env], makeFs({ modes: { [`${HOME}/certs/gw.key`]: 0o100644 } })));
    expect(r.evidence?.map(e => e.file)).toEqual([`${HOME}/certs/gw.key`]);
  });

  it('OSH-008 checks the snap gateway state under ~/snap/openshell/common', async () => {
    const snapState = `${HOME}/snap/openshell/common/.local/state/openshell`;
    const fs = makeFs({ modes: { [`${snapState}/tls/ca.key`]: 0o100644, [`${snapState}/gateway/openshell.db`]: 0o100644 } });
    const r = await check('OSH-008').run(ctx([], fs));
    expect(r.evidence?.map(e => e.file).sort()).toEqual([`${snapState}/gateway/openshell.db`, `${snapState}/tls/ca.key`]);
  });

  it('OSH-009 flags writable config and gateway metadata', async () => {
    const fs = makeFs({
      modes: { [TOML]: 0o100666, [`${CFG}/gateways/work/metadata.json`]: 0o100620, [CFG]: 0o40700 },
      dirs: { [`${CFG}/gateways`]: [{ name: 'work', dir: true }] },
    });
    const r = await check('OSH-009').run(ctx([gatewayToml({})], fs));
    expect(r.evidence!.map(e => e.file)).toEqual([TOML, `${CFG}/gateways/work/metadata.json`]);
  });

  it('OSH-010 flags OPENSHELL_GATEWAY_INSECURE and plaintext remote gateways', async () => {
    const fs = makeFs({
      env: { OPENSHELL_GATEWAY_INSECURE: '1' },
      files: {
        [`${CFG}/gateways/remote/metadata.json`]: '{"gateway_endpoint":"http://10.1.2.3:8080"}',
        [`${CFG}/gateways/local/metadata.json`]: '{"gateway_endpoint":"http://127.0.0.1:8080"}',
      },
      dirs: { [`${CFG}/gateways`]: [{ name: 'remote', dir: true }, { name: 'local', dir: true }] },
    });
    const r = await check('OSH-010').run(ctx([], fs));
    expect(r.evidence!.map(e => e.snippet)).toEqual(['OPENSHELL_GATEWAY_INSECURE=true', 'gateway_endpoint: http://10.1.2.3:8080']);
  });
});

describe('sandbox policies', () => {
  const risky = {
    version: 1,
    filesystem_policy: { read_only: ['/usr'], read_write: ['/tmp', '/etc', '/home/linuxbrew', '/home'] },
    network_policies: {
      anything: { endpoints: [{ host: 'api.github.com', port: 443 }, { host: 'up.example.com', port: 443, tls: 'skip' }], binaries: [{ path: '/**' }] },
      wide: { endpoints: [{ port: 8443, allowed_ips: ['0.0.0.0/0'] }, { port: 5432, allowed_ips: ['10.0.0.0/8', '10.0.5.20/32'] }, { host: 'host.openshell.internal', port: 5000 }], binaries: [{ path: '/usr/bin/curl' }] },
      api: { endpoints: [{ host: 'api.example.com', port: 443, protocol: 'rest', access: 'full' }, { host: 'safe.example.com', port: 443, protocol: 'rest', enforcement: 'enforce', access: 'read-only' }], binaries: [{ path: '/usr/bin/node' }] },
    },
  };

  it('reads each sandbox policy from the 0.1.x list shape and the global policy', async () => {
    const fs = cliFs({ sandboxes: [{ name: 'box', workspace: 'team-a' }, { name: '--evil', workspace: 'x' }] }, { 'team-a/box': risky }, risky);
    const c = ctx([], fs, { cli: '/usr/bin/openshell' });
    const r = await check('OSH-011').run(c);
    expect(r.evidence!.map(e => e.file)).toEqual(['openshell sandbox team-a/box', 'openshell global policy']);
    // option-like names never reach the CLI
    const calls = (fs.exec as ReturnType<typeof vi.fn>).mock.calls.map(([, args]) => args.join(' '));
    expect(calls.some(a => a.includes('--evil'))).toBe(false);
  });

  it('queries a sandbox listed without a workspace in the default workspace', async () => {
    const fs = cliFs({ sandboxes: [{ name: 'box' }, { name: 'box2', workspace: '' }] }, { 'default/box': risky, 'default/box2': risky });
    const r = await check('OSH-014').run(ctx([], fs, { cli: '/usr/bin/openshell' }));
    expect(r.evidence?.map(e => e.file)).toEqual(['openshell sandbox default/box', 'openshell sandbox default/box2']);
  });

  it('OSH-011 flags match-everything and whole-bin-directory globs, not narrow ones', async () => {
    const policy = (paths: string[]) => ({ network_policies: { r: { endpoints: [{ host: 'a.example.com', port: 443 }], binaries: paths.map(path => ({ path })) } } });
    const broad = ['/**/*', '/*/**', '/usr/bin/*', '/bin/**', '/usr/local/sbin/*', '/home/*/**'];
    const narrow = ['/usr/bin/curl', '/usr/lib/jvm/*/bin/java', '/sandbox/.venv/bin/*'];
    const fs = cliFs({ sandboxes: [{ name: 'b', workspace: 'default' }, { name: 'n', workspace: 'default' }] }, { 'default/b': policy(broad), 'default/n': policy(narrow) });
    const r = await check('OSH-011').run(ctx([], fs, { cli: 'openshell' }));
    expect(r.evidence?.map(e => e.snippet)).toEqual([`network_policies.r.binaries: ${broad.join(', ')}`]);
  });

  it('OSH-014 flags system subtrees but not ordinary writable dirs', async () => {
    const policy = { filesystem_policy: { read_write: ['/usr/lib', '/usr/sbin', '/usr/share', '/etc/ssl', '/tmp', '/dev/null', '/var/tmp', '/home/u/work', '/sandbox'] } };
    const fs = cliFs({ sandboxes: [{ name: 'b', workspace: 'default' }] }, { 'default/b': policy });
    const r = await check('OSH-014').run(ctx([], fs, { cli: 'openshell' }));
    expect(r.evidence?.[0].snippet).toBe('filesystem_policy.read_write: /usr/lib, /usr/sbin, /usr/share, /etc/ssl');
  });

  it('OSH-012 reports raw TCP passthrough endpoints', async () => {
    const policy = { network_policies: { db: { endpoints: [{ host: 'db.example.com', port: 5432, protocol: 'tcp' }], binaries: [{ path: '/usr/bin/psql' }] } } };
    const fs = cliFs({ sandboxes: [{ name: 'b', workspace: 'default' }] }, { 'default/b': policy });
    const r = await check('OSH-012').run(ctx([], fs, { cli: 'openshell' }));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('info');
    expect(r.evidence?.[0].snippet).toContain('protocol: tcp');
  });

  it('reads the 0.0.x bare-array list shape', async () => {
    const fs = cliFs([{ name: 'my-assistant', workspace: 'default' }], { 'default/my-assistant': risky });
    const r = await check('OSH-014').run(ctx([], fs, { cli: '/usr/bin/openshell' }));
    expect(r.evidence?.[0].snippet).toBe('filesystem_policy.read_write: /etc, /home');
  });

  it('reads $OPENSHELL_SANDBOX_POLICY without a CLI', async () => {
    const yaml = 'version: 1\nnetwork_policies:\n  r:\n    endpoints: [{ host: a.example.com, port: 443 }]\n    binaries: [{ path: "/usr/**" }]\n';
    const fs = makeFs({ env: { OPENSHELL_SANDBOX_POLICY: '/p/policy.yaml' }, files: { '/p/policy.yaml': yaml } });
    const r = await check('OSH-011').run(ctx([], fs));
    expect(r.evidence?.[0].file).toBe('/p/policy.yaml');
  });

  it('OSH-012 grades uninspected endpoints', async () => {
    const r = await check('OSH-012').run(ctx([], cliFs({ sandboxes: [{ name: 'box', workspace: 'default' }] }, { 'default/box': risky }), { cli: 'openshell' }));
    expect(r.severity).toBe('warning');
    const snippets = r.evidence!.map(e => e.snippet!.split(': ').slice(1).join(': '));
    expect(snippets).toEqual(expect.arrayContaining(['tls: skip', 'no protocol', 'access: full', 'enforcement: audit (default)']));
    expect(snippets.filter(s => s.startsWith('enforcement'))).toHaveLength(1);
  });

  it('OSH-013 flags /0 as critical, /8 and the gateway host as warnings, not /32', async () => {
    const r = await check('OSH-013').run(ctx([], cliFs({ sandboxes: [{ name: 'box', workspace: 'default' }] }, { 'default/box': risky }), { cli: 'openshell' }));
    expect(r.severity).toBe('critical');
    expect(r.evidence!.map(e => e.snippet!.split(': ').pop())).toEqual(['allowed_ips 0.0.0.0/0', 'allowed_ips 10.0.0.0/8', 'network_policies.wide → host.openshell.internal:5000']);
  });

  it('OSH-013 leaves allowed_ips that constrain a named host alone (NemoClaw local-inference preset)', async () => {
    const preset = {
      version: 1,
      network_policies: {
        local_inference: {
          endpoints: [{ host: 'inference.lan', port: 11434, protocol: 'rest', enforcement: 'enforce', allowed_ips: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'] }],
          binaries: [{ path: '/usr/bin/curl' }],
        },
      },
    };
    const r = await check('OSH-013').run(ctx([], cliFs({ sandboxes: [{ name: 'box', workspace: 'default' }] }, { 'default/box': preset }), { cli: 'openshell' }));
    expect(r.passed).toBe(true);
  });

  it('never attributes the scanning user\'s gateway or environment to another user\'s install', async () => {
    const fs = cliFs({ sandboxes: [{ name: 'box', workspace: 'default' }] }, { 'default/box': risky }, undefined, {
      env: { OPENSHELL_GATEWAY_INSECURE: '1', OPENSHELL_SANDBOX_POLICY: '/p.yaml' },
      modes: { '/home/other/.local/state/openshell/tls/ca.key': 0o100644 },
    });
    const other: ScanContext = {
      installation: { agent: 'openshell', installDir: '/home/other/.config/openshell', configFiles: [], cliBinary: 'openshell', user: 'other' },
      configs: [], platform: 'linux', fs,
    };
    expect((await check('OSH-011').run(other)).passed).toBe(true);
    expect((await check('OSH-010').run(other)).passed).toBe(true);
    expect(fs.exec).not.toHaveBeenCalled();
    // …while its own files are checked under its home
    expect((await check('OSH-008').run(other)).evidence?.[0].file).toBe('/home/other/.local/state/openshell/tls/ca.key');
  });

  it('passes when the gateway is unreachable', async () => {
    for (const id of ['OSH-011', 'OSH-012', 'OSH-013', 'OSH-014']) {
      expect((await check(id).run(ctx([], makeFs(), { cli: 'openshell' }))).passed, id).toBe(true);
    }
  });
});
