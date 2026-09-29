# Auto-Fix Criteria

`vaso fix` auto-remediates **36 of 318 checks** (≈11%). The other 282 surface findings and remediation guidance only. This document explains where the line is drawn, why, and exactly what VASO writes when it does fix.

## The Rule

A check is auto-fixable if and only if **VASO can compute the correct value without asking the user**.

That single criterion produces the entire fixable/not-fixable split. There is no severity threshold, no opt-in flag for "destructive" fixes, no allowlist of safe categories. If the remediation requires identity data, secret material, a trust policy, or a path that lives outside the config schema, VASO refuses to guess and leaves the finding as guidance.

## How the Boundary Is Enforced in Code

The contract is declarative, per-check, in the check module itself. Two coupled signals:

1. **`fixable: true`** in the result returned by `run()` (`src/core/check-builder.ts`). Surfaces "FIXABLE" in scan output and qualifies the finding for the fix queue.
2. **`fix(ctx)`** function on the check module. The actual remediation handler.

A check is treated as fixable iff **both** are present. The fix command filters on `result.fixable && check.fix` (`src/remediation/engine.ts`); either one alone is ignored. There is no heuristic and no runtime introspection — the boundary is whatever the check author declared.

## What Is Auto-Fixable

The 36 fixable checks fall into four patterns. In each case there is a single opinionated correct value VASO can write blindly.

### Bind to loopback

Replace public-bound listeners with `127.0.0.1`.

| Check | Field | Written value |
|---|---|---|
| CFG-001 | `gateway.host` (or `GATEWAY_HOST` for env) | `127.0.0.1` |
| IC-001 | `[webui].listen_host` (current) / `HTTP_HOST`, `GATEWAY_HOST` (0.x) | `127.0.0.1` |
| ZC-003 | `gateway.host`, `gateway.allow_public_bind` | `127.0.0.1`, `false` |

### Setting to safe default

| Check | Field | Written value |
|---|---|---|
| CFG-008 | `sandbox` (or `SANDBOX`) | `true` |
| CFG-010 | `rateLimit` (or `RATE_LIMIT`) | `{ max: 60, window: "1m" }` (`60/1m`) |
| CFG-012 | `auth.bypass` (or `AUTH_BYPASS`) | `false` |
| CFG-013 | `dm.policy` (or `DM_POLICY`) | `restricted` |
| IC-005 | `SANDBOX_ENABLED` / `sandbox.enabled` (0.x) | `true` |
| IC-006 | `[boot].profile` (current) / `SANDBOX_POLICY` (0.x) | `local-dev` / `readonly` |
| IC-007 | `[policy].default_approval_policy` (current) / `AGENT_AUTO_APPROVE_TOOLS` (0.x) | `ask_destructive` / `false` |
| IC-008 | `ALLOW_LOCAL_TOOLS` (0.x) | `false` |
| IC-012 | `sandbox.auto_pull_image` / `SANDBOX_AUTO_PULL` (0.x) | `false` |
| NB-003 | `tools.restrictToWorkspace` | `true` |
| ZC-001 | `secrets.encrypt` | `true` (secrets must then be re-entered) |
| ZC-004 | `gateway.require_pairing` | `true` |
| ZC-005 | `risk_profiles.<alias>.level` on full-autonomy profiles | `supervised` |
| ZC-006 | `workspace_only` / `agents.<alias>.workspace.unrestricted_filesystem` | `true` / `false` |
| ZC-008 | `skills.open_skills_enabled`, `skills.allow_scripts` | `false` |
| ZC-011 | risk-profile `auto_approve` | `browser` removed |
| ZC-012 | `http_request.allow_private_hosts` | `false` |
| ZC-014 | risk-profile `sandbox_enabled` (and `sandbox_backend` when `none`) | `true` (`auto`) |
| ZC-016 | `gateway.allow_self_upgrade`, `trust_forwarded_headers`, `allow_remote_admin`; zeroed rate limits | `false`; pair `10`/min, webhook `60`/min |
| LY-001 | `LYRIE_SHIELD_MODE` | `active` (was passive or invalid) |
| LY-009 | `LYRIE_LOCAL_DRY_RUN` | `false` |
| LY-018 | `NODE_ENV` | `production` (was development) |
| AT-002 | `agent.readScope` | `working-dir` |
| AT-003 | `http.approvalMode` | `writes` |
| PCL-001 | `agents.defaults.restrict_to_workspace` | `true` |
| PCL-002 | `tools.exec.enable_deny_patterns` | `true` |
| PCL-004 | `tools.exec.allow_remote` | `false` |

### Restrictive file mode

`chmod 600` on credential-bearing files (`700` on directories).

| Check | Target |
|---|---|
| CFG-003 | adapter-declared credential paths |
| CFG-020 | NemoClaw `~/.nemoclaw/credentials.json` |
| OC-006 | OpenClaw memory files (`memory.json`, `conversations.db`) |
| NC-002 | `~/.config/nanoclaw/` (700) and its allowlist/secret files (600) |
| ZC-013 | ZeroClaw `.secret_key` |

### Inject an opinionated default list

When the security posture requires a baseline list and any reasonable user wants the same baseline:

| Check | Field | Written value |
|---|---|---|
| CFG-005 | `security.safeBins` (or `SAFE_BINS` for env) | `ls, cat, grep, head, tail, wc, echo, date` (8 read-only utilities) |

## What Is Not Auto-Fixable

Five reasons. Each rules out auto-fix even when the finding is critical.

| Reason | Example checks | Why VASO refuses |
|---|---|---|
| Identity data required | NB-001 channel `allowFrom`; IC-010 `TELEGRAM_OWNER_ID` | VASO doesn't know which users you trust |
| Trust-policy input required | IC-011 sandbox domains; NB-005 SSRF whitelist; PCL-007 tool path allowances | VASO doesn't know which domains or paths you trust |
| Secret material required | NB-002 plaintext keys; ZC-002 XOR re-encrypt; IC-009 keychain migration | The fix requires entering a fresh credential or invoking an external secrets manager |
| User-driven workflow | NB-012 npx → pinned install; CD-005 unsigned MCPB extension | The fix is a multi-step process, not a single config write |
| External resource required | IC-002 cleartext LLM endpoint — needs an HTTPS endpoint; CG-005 codesign mismatch | The fix requires resources VASO can't generate |

For all of the above, the check's `fixDescription` is still surfaced in scan output so users see the remediation step. They just don't get told the scanner will perform it.

## Safety

**Backup, always, before any write.** `src/remediation/engine.ts` copies every file in the finding's `evidence` list to `~/.vaso/backups/<ISO-timestamp>/<original-path>/` before invoking `check.fix()`. One timestamped directory per `vaso fix` invocation. There is no flag to disable backups.

**Rollback.** `vaso fix --rollback` restores from the most recent backup directory. Useful when an opinionated default doesn't match your environment (e.g. you actually do want `0.0.0.0` because the listener is behind a trusted reverse proxy).

**Non-interactive guard.** When stdin is not a TTY (CI, scripted runs), VASO refuses to apply fixes unless `--yes` is passed explicitly. There is no implicit auto-apply.

**Dry-run.** `vaso fix --dry-run` walks the same path and prints what would be written without touching disk.

## Adding a New Fixable Check

If you're authoring a check and considering whether to make it fixable, ask:

> Can I write `fix(ctx)` as a pure function of `ctx.configs` and adapter-derived state — no user prompts, no secret entry, no path discovery beyond what the adapter already declares?

If yes, declare `fixable: true` in the `run()` result and implement `fix()` using the writers in `src/remediation/config-writer.ts` (`updateJsonFile`, `updateTomlFile`, `updateEnvFile`, `chmodFile`). If no, return `fixable: false` (or omit the field) and rely on `fixDescription` to surface the manual remediation guidance.

The 14 checks cleaned up in an earlier commit chain (`NB-001/002/008/010/012`, `ZC-002/007/009/011/012`, `IC-002/009/010/011`) violated this rule — they declared `fixable: true` paired with a stub `fix()` that returned `applied: false` and "Manual action required". Either pattern alone — `fixable: false` with no `fix()`, or `fixable: true` with a working `fix()` — is honest; the hybrid is not. ZC-011 and ZC-012 have since regained working fixes that write a single safe value (drop `browser` from `auto_approve`; set `allow_private_hosts = false`); narrowing their host allowlists remains manual.
