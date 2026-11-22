# Network Scanning Guide

VASO can scan remote hosts for AI agent security issues without requiring Node.js or any runtime on the target machine. It uses a lightweight Go probe binary that collects data, and the scanner analyzes it locally.

## Three scanning modes

| Mode | Command | Use case |
|------|---------|----------|
| SSH (live) | `vaso scan --host user@host` | Ad-hoc scans, small teams |
| Snapshot (offline) | `vaso scan --snapshot file.json` | Airgapped, CI pipelines |
| Inventory (fleet) | `vaso scan --inventory hosts.yaml` | Multiple hosts at once |

---

## Getting the probe

You do **not** build the probe yourself in the normal case — and you get the same behavior whether you **installed** VASO (`curl … | bash` / `npm install -g` the release tarball, as in the [README](../README.md#installation)) or **cloned and built** it. No Go toolchain is required on your machine.

Probe binaries exist for **Linux and macOS, amd64 and arm64** only. On each remote scan, VASO:

1. detects the target's OS/arch over SSH (`uname -s && uname -m`),
2. uses a locally-built binary in `probe/dist/` of the VASO tree if one is present (a source checkout after `cd probe && make` — this always wins and is not checksum-verified, since you built it), otherwise
3. uses the cached copy under `~/.vaso/probe/<version>/` if its SHA-256 still matches, otherwise
4. downloads the single `vaso-probe-<os>-<arch>` asset from the GitHub Release matching your VASO version, verifies its SHA-256 against `probe/checksums.json` (which ships inside the VASO package), and caches it under `~/.vaso/probe/<version>/`.

A checksum mismatch aborts the scan — VASO never runs an unverified downloaded probe. After the first fetch the cached binary is reused with no network access.

You only need to [build the probe yourself](#building-the-probe-binaries) if you're developing the probe, running an unreleased build that has no matching release assets, or operating fully air-gapped.

---

## SSH remote scanning

Scan a remote host in a single command. VASO pushes the probe binary over SSH, executes it, and brings the results back.

### Basic usage

```bash
# Scan a single host
vaso scan --host alice@10.0.0.5

# Scan with a specific SSH key
vaso scan --host alice@10.0.0.5 --ssh-key ~/.ssh/prod_key

# Scan with a custom port
vaso scan --host alice@10.0.0.5:2222

# Multiple hosts in parallel
vaso scan --host root@10.0.0.5 --host root@10.0.0.6 --host root@10.0.0.7
```

A target is always `user@host[:port]` (IPv6: `user@[::1]:2222`); a target without a user is rejected.

### Password authentication

VASO supports password-based SSH authentication. It establishes a single ControlMaster connection with full terminal access, prompting for the password once. All subsequent operations (file transfer, probe execution, cleanup) reuse that authenticated connection without re-prompting.

```bash
vaso scan --host alice@10.0.0.5
# alice@10.0.0.5's password: ********
# (scans proceed with no further prompts)
```

Key-based authentication works without any prompts if the key is in your SSH agent or specified with `--ssh-key`.

### SSH configuration and host keys

VASO runs your system `ssh`/`scp`, so `~/.ssh/config` applies for host aliases, jump hosts (`ProxyJump`) and similar settings. Two things are always set on the command line and therefore take precedence over `~/.ssh/config`:

- the **user and port** from the target (`user@host[:port]`, port 22 when omitted) — a `User` or `Port` line in `~/.ssh/config` is not used;
- **`StrictHostKeyChecking=accept-new`** — a host you have never connected to is accepted and its key recorded in `known_hosts` on first connect; a host whose key has **changed** is refused. If you need strict first-contact verification, add the host keys to `known_hosts` before the first scan.

### Privilege and multi-user coverage

Two things decide which users' agents are scanned: the privilege the probe runs with **and** the `--all-users` flag.

| Probe runs as | Without `--all-users` | With `--all-users` |
|---------------|-----------------------|--------------------|
| a regular user (`alice@host`) | `/home/alice` only | `/home/alice` only, plus a warning |
| root (`root@host`, or `--sudo` with passwordless sudo) | root's own home only (`/root`) | every home under `/home` (`/Users` on macOS) plus `/root` |

**Full fleet coverage needs both root and `--all-users`:**

```bash
# Connect as root
vaso scan --host root@10.0.0.5 --all-users

# Connect as a regular user and escalate with passwordless sudo
vaso scan --host alice@10.0.0.5 --sudo --all-users

# Same for discovery only
vaso detect --host root@10.0.0.5 --all-users
```

`--all-users` is accepted by both `vaso scan` and `vaso detect`; `--sudo` is `scan`-only, so `vaso detect` covers other users only when it connects as root.

**What VASO prints when coverage is limited:**

- **Regular user with `--all-users`** — the host's progress line is followed by:
  ```
    ✓ alice@10.0.0.5 (9129ms) — score 51/100, 11C / 32W / 20I
      ! --all-users needs root to read other users' homes; only /home/alice was covered (run as root, or add --sudo for remote hosts)
  ```
  (`vaso detect` prints the same message prefixed with the host label.)
- **Regular user without `--all-users`** — no warning; the scan covers the connecting user's home, which is what was asked for.
- **`--sudo` when the remote user has no passwordless sudo** — the probe cannot escalate (it never prompts for a sudo password), runs as the connecting user, and the scan goes on. VASO prints a warning under the host's result:

  ```
  ! --sudo requested but the probe ran as "deploy", not root (no passwordless sudo on the host) — only files that user can read were scanned
  ```
- **Scanning a snapshot collected as a non-root user** (`vaso scan --snapshot`) — VASO prints `Warning: snapshot collected as non-root user "alice" — scan coverage may be limited.`

### SSH options

| Flag | Description | Default |
|------|-------------|---------|
| `--host <user@host[:port]>` | Remote target (repeatable) | — |
| `--inventory <path>` | YAML file listing hosts to scan | — |
| `--ssh-key <path>` | SSH identity file. Applies to every `--host` target; for inventory hosts it only fills in hosts whose entry sets no `identity`. A key file that doesn't exist or can't be read stops the scan (exit 2) instead of falling back to other keys | System default |
| `--ssh-timeout <seconds>` | Per-attempt connection timeout (1–86400); uploading and running the probe have their own 10-minute limit | 60 |
| `--ssh-retries <n>` | Additional SSH attempts after the first failure (0–10) | 0 |
| `--parallel <n>` | Max hosts to scan concurrently | 5 |
| `--sudo` | Run the probe with passwordless sudo on every host (`scan` only) | false |
| `--all-users` | Scan every user's home — needs the probe to run as root (see above) | false |
| `--save-snapshot <dir>` | Write each host's collected snapshot to `<dir>/<hostname>.json` (mode 0600) | — |
| `--output-dir <dir>` | Write one report per host to `<dir>/<hostname>.<ext>` (mutually exclusive with `-o`; local `vaso scan` uses the local hostname) | — |
| `--silent` | Suppress all stdout/stderr chatter; requires `-o` or `--output-dir` | false |

All flags except `--sudo` are accepted by both `vaso scan` and `vaso detect`. `vaso detect` writes `terminal` or `json` only.

### How it works

1. **Authenticate** — establishes an SSH ControlMaster connection (password/key prompt happens here, once)
2. **Detect platform** — runs `uname -s && uname -m` to identify OS and architecture
3. **Push probe** — copies the matching `vaso-probe` binary and a collection manifest to `/tmp/vaso-probe-<id>` and `/tmp/vaso-manifest-<id>.json` on the remote host
4. **Execute** — runs the probe remotely (with `--escalate` when `--sudo` is set); it collects what the manifest lists — see [Privacy](#privacy)
5. **Analyze** — parses the probe's JSON output (held to the same shape and size checks as a `--snapshot` file) and runs all checks locally
6. **Clean up** — removes the probe binary and manifest from the remote host and closes the connection

The cleanup runs even when the scan fails after connecting. Nothing VASO uploads is left on the remote host.

---

## Inventory-based scanning

For scanning multiple hosts, define them in a YAML inventory file.

### Inventory format

```yaml
hosts:
  - host: 10.0.0.5
    user: root
    label: prod-agent-01

  - host: 10.0.0.6
    user: alice
    port: 2222
    sudo: true
    label: prod-agent-02

  - host: staging.internal
    user: root
    identity: ~/.ssh/staging_key
    label: staging

  # user@host[:port], as with --host
  - host: alice@10.0.0.8:2222
    label: dev-box
```

### Run the scan

```bash
vaso scan --inventory hosts.yaml --all-users
vaso scan --inventory hosts.yaml --all-users -f json -o fleet-report.json
```

### How CLI flags combine with the inventory

| Setting | `--host` targets | Inventory hosts |
|---------|------------------|-----------------|
| `--ssh-key` | used for every target | used only where the entry has no `identity`; a host's own `identity` wins |
| `--sudo` | sudo on every target | sudo on every host, whatever the entry's `sudo:` says (an entry cannot opt out) |
| `--all-users`, `--ssh-timeout`, `--ssh-retries`, `--parallel` | apply to the whole run | apply to the whole run |

```bash
# Force sudo on all hosts
vaso scan --inventory hosts.yaml --sudo --all-users

# Fill in a key for hosts that don't name one
vaso scan --inventory hosts.yaml --ssh-key ~/.ssh/fleet_key

# Scan 20 hosts in parallel with 2 retry attempts on transient SSH failures
vaso scan --inventory hosts.yaml --parallel 20 --ssh-retries 2
```

`--host` and `--inventory` can be combined; a target listed twice is scanned once.

### Per-host fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `host` | yes | — | Hostname or IP, or `user@host[:port]` (a `user`/`port` field that contradicts it is an error) |
| `user` | no | `root` | SSH username |
| `port` | no | `22` | SSH port |
| `identity` | no | `--ssh-key`, else system default | Path to SSH key; wins over `--ssh-key` |
| `sudo` | no | `false` | Run the probe with passwordless sudo (`true`/`false`, not strings) |
| `label` | no | `user@host` (`user@host:port` when the port isn't 22) | Name in progress lines, reports and baselines; must be non-empty and unique |

Any other field (a typo such as `sshKey:`) is rejected with an error naming the expected fields, rather than being silently ignored.

---

## Performance and resilience

### Live progress

While a fleet scan is in flight, VASO prints one line per host as it completes — even before the rest of the fleet finishes. A slow host won't blank your terminal until the end:

```
  Scanning 3 remote host(s)...

  ✗ prod-agent-03 (5004ms): SSH connection to alice@10.0.0.7 timed out after 5s (host unreachable or not answering; raise --ssh-timeout if it is just slow)
  ✓ prod-agent-01 (9129ms) — score 51/100, 11C / 32W / 20I
  ✓ prod-agent-02 (8923ms) — score 92/100, 0C / 1W / 2I
```

Each line shows the per-host duration, the score, and a finding-count summary (critical / warning / info); per-host warnings follow on lines starting with `!`. Failures show the first line of the error message.

### Per-host report files (`--output-dir`)

`-o file.json` aggregates all per-host results into one combined JSON document. For other formats — particularly **SARIF** and **JUnit XML**, which can't be safely text-concatenated — write one file per host with `--output-dir`:

```bash
vaso scan --inventory hosts.yaml -f sarif --output-dir ./sarif/
# Writes ./sarif/agent-01.sarif, ./sarif/agent-02.sarif, ...
# (named after each host's own hostname, not its inventory label)
```

The directory is created if it doesn't exist. Filenames are the **hostname the host reports** (sanitized to `[A-Za-z0-9._-]`), not the inventory label, with the format's natural extension: `.json`, `.sarif`, `.md`, `.html`, `.csv`, `.xml` for JUnit, `.txt` for terminal. If two targets report the same hostname (two users on one machine, cloned VMs), the first keeps `<hostname>.<ext>` and the next is written as `<hostname>--<label>.<ext>`, so nothing is overwritten.

`-o` and `--output-dir` are mutually exclusive. A single-host scan can write SARIF or JUnit to `-o` or stdout; with several hosts, `-f sarif`/`-f junit` without `--output-dir` is rejected with a pointer to `--output-dir`. Progress lines go to stderr, so `vaso scan --host … -f json | jq` receives just the JSON host array.

### Silent mode (`--silent`)

For scripted / cron / CI use, suppress all progress chatter. The report still goes to the file; nothing else is printed:

```bash
vaso scan --inventory hosts.yaml -o fleet-report.json --silent
vaso scan --inventory hosts.yaml --output-dir ./reports/ -f sarif --silent
```

`--silent` requires `-o` or `--output-dir` — there's no point in suppressing console output if the report itself is going to stdout. The CLI exits 2 with a clear error if you forget. The same rule applies to local scans. `--output-dir` also works for a local `vaso scan`: the report is written to `<dir>/<local-hostname>.<ext>`.

When `--silent` is set, the global VASO banner, IOC/advisory feed warnings, plugin/rule warnings, retry banners, save-snapshot lines, per-host progress and warnings, the "Report written to" notice, and ssh's own stderr (host-key notices, connection messages — printed with `--debug`) are all suppressed; password prompts still appear, since ssh asks on the terminal itself. Errors and validation failures still print to stderr.

If `-o <path>` points at a nested path whose parent directories don't exist (e.g. `-o reports/run-1/host.json`), VASO creates them before writing.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Every host scanned, no finding at or above `--fail-on` (default `critical`) |
| 1 | Findings at or above `--fail-on` |
| 2 | VASO could not do its job: invalid usage, an unreadable `--ssh-key` or inventory, or a report/snapshot/baseline file that could not be written (takes precedence over 3) |
| 3 | Scan incomplete: at least one host could not be scanned — unreachable, authentication failed, or its probe output failed the checks a `--snapshot` file gets (not JSON, wrong shape, over the size limits) — **or** a check errored on a scanned host. Takes precedence over 1; the reason is recorded in the report |

`vaso detect` uses the same codes for unscanned hosts.

### Concurrency (`--parallel`)

By default, VASO scans up to 5 hosts at a time. Tune this for your environment:

```bash
# Big fleet, fast network — scan 20 hosts at once
vaso scan --inventory hosts.yaml --parallel 20

# Constrained environment — scan one at a time
vaso scan --inventory hosts.yaml --parallel 1
```

VASO uses a true worker pool: as soon as one host finishes, the next queued host starts. A slow host won't block faster ones queued behind it.

### Retries on transient SSH failures (`--ssh-retries`)

By default, a single SSH failure (network blip, slow control-master, etc.) marks the host failed and moves on. To retry:

```bash
# Retry up to 2 times on failure (3 total attempts per host)
vaso scan --inventory hosts.yaml --ssh-retries 2
```

`--ssh-retries` accepts 0–10. Backoff is exponential: 1s before the first retry, 2s before the second, 4s before the third, capped at 8s. Each retry uses a fresh probe file name on the remote host, so it cannot collide with a half-cleaned-up previous attempt.

Retries are only useful for transient errors. Misconfigurations (bad SSH key, wrong port, hostname not resolving) will fail every attempt and waste time. Start with `--ssh-retries 0` and only raise it once you observe transient failures in practice.

When a retry happens, VASO prints a banner before each new attempt:

```
  Retry 1/2 for 10.0.0.7: Connection reset by peer
  Retry 2/2 for 10.0.0.7: SSH connection to alice@10.0.0.7 timed out after 60s (...)
```

### Collect once, scan many times (`--save-snapshot`)

For repeatable scanning, fetch each host's snapshot once and re-scan it offline as many times as you need — against new baselines, new rule files, or after a check-engine upgrade — without re-paying the SSH round-trip:

```bash
# Step 1: collect snapshots from the whole fleet (one SSH session per host)
vaso scan --inventory hosts.yaml --save-snapshot ./snapshots/
#   Saved snapshot for 10.0.0.5 → ./snapshots/agent-01.json

# Step 2: re-scan offline whenever you want
vaso scan --snapshot ./snapshots/agent-01.json --all-users
vaso scan --snapshot ./snapshots/agent-02.json --diff
```

`--save-snapshot <dir>` writes one file per host to the named directory, named after the **hostname the host reports** (sanitized to `[A-Za-z0-9._-]`), not the inventory label, with the same `<hostname>--<label>.json` rule for duplicate hostnames as `--output-dir`. The directory is created if it doesn't exist. Snapshot files are written **owner-only (mode 0600)** because they contain collected file contents — see [Privacy](#privacy). Report files are written with your normal umask. With `-f json`, give `--save-snapshot` and `--output-dir` different directories — both would name a host's file `<hostname>.json`, so VASO refuses the pair (exit 2).

The same flag exists on `vaso detect`, useful for inventorying agent installs across a fleet without running checks.

---

## Snapshot scanning (offline / airgapped)

For hosts with no direct SSH access from the scanner — airgapped systems, restricted networks, or CI pipelines.

### Step 1: Generate a manifest

On the scanner machine:

```bash
vaso probe manifest > manifest.json
```

This produces a JSON file listing every config file, directory, command, and environment variable the scanner needs. It's the only thing the probe collects.

### Step 2: Run the probe on the target

Transfer the probe binary (from `~/.vaso/probe/<version>/`, a GitHub Release, or your own `probe/dist/`) and the manifest to the target (USB, SCP, CI artifact, etc.):

```bash
# On the target host (no Node.js needed)
./vaso-probe --manifest manifest.json > snapshot.json

# As root, for multi-user coverage (scan it with --all-users)
sudo ./vaso-probe --manifest manifest.json > snapshot.json

# Re-run itself under passwordless sudo if available; otherwise prints
# "Warning: --escalate requested but passwordless sudo is not available" and runs unprivileged
./vaso-probe --manifest manifest.json --escalate > snapshot.json
```

The probe binary is a static Go executable. It runs on bare Linux and macOS with zero dependencies. Restrict the output file's permissions (e.g. `umask 077` first) — a shell redirect creates it with your default umask.

### Step 3: Scan the snapshot

Transfer `snapshot.json` back to the scanner:

```bash
vaso scan --snapshot snapshot.json
vaso scan --snapshot snapshot.json --all-users          # root snapshot: every user
vaso scan --snapshot snapshot.json -f sarif -o results.sarif
```

### Validate a snapshot

Check that a snapshot file is well-formed before scanning:

```bash
vaso probe validate snapshot.json
# Snapshot: snapshot.json
#   Host:      prod-agent-01
#   Platform:  linux
#   Timestamp: 2026-11-17T10:00:00Z
#   Files:     1552 collected
#   Dirs:      79 collected
#   Commands:  136 collected
#   Privilege:  root (root)
#   Users:     root, alice, bob
# Snapshot is valid.
```

---

## Building the probe binaries

You normally **don't** need to build the probe — see [Getting the probe](#getting-the-probe) for how it's fetched and verified automatically on first use (same for an installed or a cloned VASO). No Go toolchain is required on your machine.

Build manually only when developing the probe, running an unreleased VASO build with no published release assets, or operating fully air-gapped. This needs a source checkout of VASO and Go: a binary present in the checkout's `probe/dist/` always takes precedence over the cache and the download. Cross-compile for all supported platforms:

```bash
cd probe/
make        # same as `make all`
```

This produces 4 static binaries in `probe/dist/`:

| Binary | Platform | Size |
|--------|----------|------|
| `vaso-probe-linux-amd64` | Linux x86_64 | ~3.6 MB |
| `vaso-probe-linux-arm64` | Linux ARM64 | ~3.4 MB |
| `vaso-probe-darwin-amd64` | macOS Intel | ~3.6 MB |
| `vaso-probe-darwin-arm64` | macOS Apple Silicon | ~3.4 MB |

All binaries are statically linked (`CGO_ENABLED=0`), built with `-trimpath -buildvcs=false` (reproducible from the release tag), with no runtime dependencies.

The SSH scanning mode automatically selects the correct binary based on the remote host's `uname` output.

---

## Output formats

All scanning modes support the same output formats:

```bash
# Terminal (default)
vaso scan --host root@10.0.0.5

# JSON
vaso scan --host root@10.0.0.5 -f json -o report.json

# SARIF (GitHub Code Scanning)
vaso scan --host root@10.0.0.5 -f sarif -o results.sarif

# Markdown
vaso scan --host root@10.0.0.5 -f markdown -o report.md

# HTML
vaso scan --host root@10.0.0.5 -f html -o report.html
```

CSV and JUnit (`-f csv`, `-f junit`) work too. For multi-host terminal output, each host's report is introduced by a `── <label> (<reported hostname>) ──` header, followed by any failed hosts and a summary:

```
── prod-agent-01 (agent-01) ──

VASO Security Scan Report
Timestamp: 2026-11-17T10:00:00.000Z

Agent: openclaw (user: root)
  Install: /root/.openclaw
  Score: 68 (D)
  ...

── prod-agent-02 (agent-02) ──

VASO Security Scan Report
  ...

  Failed hosts (1):
    ✗ prod-agent-03: SSH connection to alice@10.0.0.7 timed out after 5s (host unreachable or not answering; raise --ssh-timeout if it is just slow)

  Summary: 2 scanned, 1 failed
```

The headers, failed-host list and summary go to stderr; the reports themselves go to stdout.

---

## Privacy

A remote scan copies data from the target to the scanning machine. This is what the probe collects and what it keeps out.

**What is collected**

- **Only manifest-listed paths.** The probe reads the config files, globs, directory listings and system paths in the manifest that `vaso probe manifest` prints — agent configs, skill trees, MCP configs, install metadata — under the scanned homes. It does not walk the rest of the filesystem. A probe running as **root** expands these paths for every home on the host (and records them in the snapshot) even without `--all-users`; `--all-users` only decides whether VASO analyses them.
- **Conversation and history stores are metadata only** — Codex sessions, ChatGPT conversations, Gemini chats, Copilot history and session state, Muse app data, editor `state.vscdb` and similar are recorded as existence and permissions, never content.
- **Credential and token stores are metadata only** — credential files (auth/token JSON, keystores, `credentials.toml` and the like) are recorded with permissions for the checks, never their contents. A skill that links into a credential location (`~/.ssh`, `~/.aws`, `~/.kube`, shell rc files, …) is recorded as a link; what it points to is not read.

**How secrets in collected files are handled**

Secrets inside collected config files (an API key in `.env`, a token in `settings.json`) are **disguised, not shipped**: each is replaced by a random stand-in of the same shape, so checks reach the same verdict remotely as locally. The stand-in keeps the value's length, its punctuation and the class of every character (digit, a–f, g–z, A–F, G–Z). How much of the real value stays depends on its length:

| Secret length | Real characters kept |
|---------------|---------------------|
| 24 characters or more | the first 8 and the last 4 (what reports show) |
| 16–23 characters | the first 4 |
| under 16 characters | none — only length, punctuation and character classes |

A known token prefix (e.g. `github_pat_`) is kept whole, and a weak default inside a value (`admin`, `password`, `12345`) may stay in place so the default-credential check still fires. Values that are not secrets are kept as written: placeholders (`<your-key>`, `xxxx`), environment and secret-manager references (`${OPENAI_API_KEY}`, `op://…`), URLs (credentials embedded in a URL are redacted separately), and values that read as settings rather than secrets (lowercase words, short numbers) unless they sit under a password or token key. So a disguised file still reveals which keys are set, roughly how long they are, and up to 12 characters of a long secret.

- **Environment variables** — only variables matching the manifest's agent prefixes are collected. Variables with secret-like names are replaced by a redaction marker; other values have credentials in URLs, credential-named URL parameters and token-shaped text redacted; some endpoint variables keep only the URL's origin; and some are recorded only as set/not set.
- **Command output** — stdout and stderr of the allowlisted commands the probe runs go through the same redaction.
- **Skill trees** — skill code, markdown and lockfiles ship **as written** (the skill checks need the code). Settings and env files inside a skill tree — `.env`, `.env.*`, `.json`/`.jsonc`/`.json5`, `.yaml`/`.yml`, `.toml`, `.ini`, `.cfg`, `.conf`, `.properties`, `.npmrc`, `.netrc`, `.pypirc`, `.pgpass`, `.git-credentials` — are disguised like agent configs (new in 1.4.1). A secret hard-coded in skill source code ships as written.

**Network and footprint**

- The probe itself opens no network connections; results flow back over the SSH session VASO opened. Some allowlisted agent commands it runs may contact their own services — for example the read-only OpenShell queries (`openshell sandbox list`, `openshell policy get`) talk to the OpenShell gateway, and version queries run the agent's own CLI, which may do whatever that CLI does on start-up.
- The scanning machine contacts GitHub only to download a probe binary that is not yet cached (see [Getting the probe](#getting-the-probe)).
- The probe binary and manifest are deleted from the remote host after each run, including failed runs once the connection was made.

**Treat snapshots and reports as sensitive.** Snapshots saved with `--save-snapshot` are written mode 0600, but they still hold agent configs, skill code, file listings, user names and disguised (not removed) secrets. Store them like credentials: encrypted at rest, out of version control, deleted when no longer needed. Reports show partial secret values (first 8 / last 4 characters) and file paths.

---

## Security considerations

- **Read-only** — the probe only reads files and runs allowlisted commands; agent CLIs run with a throwaway `HOME` (except the read-only OpenShell policy queries, which need the real one) so they can't initialize state in the scanned home. It never modifies agent configs on the remote host.
- **Command allowlist** — the probe only executes commands from a hardcoded allowlist (`netstat`, `ss`, `ps`, `which`, agent CLIs, etc.). Arbitrary command execution is not possible.
- **No persistence** — the probe binary and manifest are deleted from the remote host after the scan completes.
- **Sudo is explicit** — `--sudo` / `--escalate` must be explicitly passed, and only passwordless sudo is used (`sudo -n`). The probe never silently escalates privileges and never asks for a sudo password.
- **Untrusted output** — the probe's output from a possibly compromised host is held to the same shape and size limits as a `--snapshot` file; a host that returns unusable output is reported unscanned (exit 3).
- **Data handling** — see [Privacy](#privacy).

---

## Troubleshooting

### SSH connection fails

```
Permission denied (publickey,password)
```

Verify you can SSH manually first: `ssh -p <port> user@host`. If that works, VASO will too. Remember that VASO always passes the user and port from the target, so a `User`/`Port` in `~/.ssh/config` is not used.

### Host key changed

VASO uses `StrictHostKeyChecking=accept-new`: a changed host key makes ssh refuse the connection. Check why the key changed before removing the old entry (`ssh-keygen -R <host>`).

### Transient SSH failures on a flaky link

If you see intermittent `Connection reset by peer` or timeout failures against hosts that are otherwise reachable, add `--ssh-retries 2` (or higher, up to 10). VASO retries with exponential backoff. Don't crank this too high — for misconfigurations (bad key, wrong port) every attempt fails and the retry is just wasted time.

### Unsupported platform

```
Unsupported platform on 10.0.0.9: freebsd/amd64
  vaso-probe binaries are available for Linux and macOS (amd64/arm64).
```

(or `Unsupported architecture on <host>: <arch>` for anything other than x86_64/aarch64/arm64.)

Published probe binaries cover Linux and macOS (amd64/arm64), and remote scans deploy only those. The probe is plain Go, so for another Unix you can build it yourself (`cd probe && GOOS=freebsd GOARCH=amd64 go build -trimpath -o vaso-probe .`), run it on the host with the manifest from `vaso probe manifest`, and scan the result with `vaso scan --snapshot` (see the snapshot workflow above). Agent adapters are written for Linux, macOS and Windows layouts, so coverage on other systems is best-effort.

### Probe download failed

```
Failed to download vaso-probe for linux/amd64 from https://github.com/vulnex/vaso/releases/download/v1.4.2/vaso-probe-linux-amd64: ...
  Build it locally instead: cd probe && make
```

The scanning machine couldn't reach GitHub. Retry with network access, or, for offline/air-gapped use, [build the probe locally](#building-the-probe-binaries) in a source checkout (`cd probe && make`); a binary in `probe/dist/` always takes precedence over the download. Alternatively copy an already-verified binary into `~/.vaso/probe/<version>/` from a machine that has fetched it — VASO re-checks its SHA-256 before use.

### Probe asset not found (HTTP 404)

```
vaso-probe asset for linux/amd64 not found (HTTP 404 at https://github.com/vulnex/vaso/releases/download/v1.4.2/vaso-probe-linux-amd64).
  This VASO release may not publish probe binaries; build one locally: cd probe && make
```

The GitHub Release for your VASO version is not published (yet), or has no asset for that platform — typical for a build from `main` between releases. Build the probe locally (`cd probe && make` in a source checkout).

### Checksum mismatch

```
Checksum mismatch for downloaded vaso-probe-linux-amd64: expected sha256:…, got sha256:…. Refusing to use it.
```

The downloaded binary doesn't match `probe/checksums.json` from your VASO install. VASO refuses to run it. Retry (a proxy may have altered the download), or reinstall VASO so the checksum file and the release match.

### Only one user's agents were scanned

The probe ran as a regular user, or `--all-users` was not given. See [Privilege and multi-user coverage](#privilege-and-multi-user-coverage): use `root@host --all-users`, or `--sudo --all-users` with passwordless sudo. If `--sudo` is set but the remote user needs a password for sudo, the scan runs as that user and prints `--sudo requested but the probe ran as "…", not root`; with `--all-users` it also prints:

```
! --all-users needs root to read other users' homes; only /home/alice was covered (run as root, or add --sudo for remote hosts)
```

For a snapshot collected as a regular user, `vaso scan --snapshot` prints:

```
Warning: snapshot collected as non-root user "alice" — scan coverage may be limited.
```
