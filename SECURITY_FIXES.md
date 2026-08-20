# Auto-Fix Criteria

`vaso fix` auto-remediates **36 of 264 checks** (≈14%). The other 228 surface findings and remediation guidance only. This document explains where the line is drawn, why, and exactly what VASO writes when it does fix.

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
| CFG-001 | `gateway.host` | `127.0.0.1` |
| IC-001 | `HTTP_HOST` / `http.host` | `127.0.0.1` |
| IC-003 | `ORCHESTRATOR_HOST` / `orchestrator.host` | `127.0.0.1` |
| NC-004 | NanoClaw listener host | `127.0.0.1` |
| ZC-003 | ZeroClaw bind | `127.0.0.1` |

### Boolean toggle to safe default

| Check | Field | Written value |
|---|---|---|
| CFG-008 | `sandbox` | `true` |
| CFG-010 | `rateLimit` | enabled with safe defaults |
| CFG-012 | auth bypass | `false` |
| IC-005 | sandbox | `true` |
| IC-006 | sandbox full-access | `false` |
| IC-007 | `AGENT_AUTO_APPROVE_TOOLS` | `false` |
| IC-008 | local tools bypass | `false` |
| IC-012 | docker auto-pull | `false` |
| NB-003 | `restrictToWorkspace` | `true` |
| NB-005 | SSRF webfetch | restricted |
| NB-009 | session encryption | enabled |
| NB-011 | rate limit | enabled |
| ZC-001 | `secrets.encrypt` | `true` |
| ZC-004 | pairing enabled | `true` |
| ZC-005 | `autonomy.level` | `supervised` |
| ZC-006 | workspace restriction | enabled |
| ZC-008 | open skills | locked down |
| ZC-014 | OS sandbox | enabled |
| LY-001 | shield mode | `enforce` (was passive) |
| LY-009 | dry-run | disabled |
| LY-018 | `NODE_ENV` | `production` (was development) |

### Restrictive file mode

`chmod 600` on credential-bearing files.

| Check | Target |
|---|---|
| CFG-003 | adapter-declared credential paths |
| OC-006 | OpenClaw memory file |
| ZC-013 | ZeroClaw `.secret_key` |

### Inject an opinionated default list

When the security posture requires a baseline list and any reasonable user wants the same baseline:

| Check | Field | Written value |
|---|---|---|
| NB-004 | `tools.exec.denyList` | `rm, rmdir, mkfs, dd, curl, wget, nc, chmod, chown, kill, shutdown, reboot, passwd` (13 commands) |
| CFG-005 | `security.safeBins` (or `SAFE_BINS` for env) | `ls, cat, grep, head, tail, wc, echo, date` (8 read-only utilities) |
| LY-011 | WebChat CORS | restricted to localhost origins |
| CFG-020 | NemoClaw API key handling | redacted-env pattern |

## What Is Not Auto-Fixable

Five reasons. Each rules out auto-fix even when the finding is critical.

| Reason | Example checks | Why VASO refuses |
|---|---|---|
| Identity data required | NB-001 channel `allowFrom`; IC-010 `TELEGRAM_OWNER_ID` | VASO doesn't know which users you trust |
| Trust-policy input required | ZC-011/012 `allowed_domains`; IC-011 sandbox domains | VASO doesn't know which domains you trust |
| Secret material required | NB-002 plaintext keys; ZC-002 XOR re-encrypt; IC-009 keychain migration | The fix requires entering a fresh credential or invoking an external secrets manager |
| User-driven workflow | NB-012 npx → pinned install; CD-005 unsigned MCPB extension | The fix is a multi-step process, not a single config write |
| External resource required | IC-002 TLS — needs your cert/key paths; CG-005 codesign mismatch | The fix requires files VASO can't generate |

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

The 14 checks cleaned up in this commit chain (`NB-001/002/008/010/012`, `ZC-002/007/009/011/012`, `IC-002/009/010/011`) violated this rule — they declared `fixable: true` paired with a stub `fix()` that returned `applied: false` and "Manual action required". Either pattern alone — `fixable: false` with no `fix()`, or `fixable: true` with a working `fix()` — is honest; the hybrid is not.
