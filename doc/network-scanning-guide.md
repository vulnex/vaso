# Network Scanning Guide

VASO can scan remote hosts for AI agent security issues without requiring Node.js or any runtime on the target machine. It uses a lightweight Go probe binary that collects data, and the scanner analyzes it locally.

## Three scanning modes

| Mode | Command | Use case |
|------|---------|----------|
| SSH (live) | `vaso scan --host user@host` | Ad-hoc scans, small teams |
| Snapshot (offline) | `vaso scan --snapshot file.json` | Airgapped, CI pipelines |
| Inventory (fleet) | `vaso scan --inventory hosts.yaml` | Multiple hosts at once |

---

## SSH remote scanning

Scan a remote host in a single command. VASO pushes the probe binary over SSH, executes it, and streams the results back.

### Basic usage

```bash
# Scan a single host
vaso scan --host root@192.168.1.50

# Scan with a specific SSH key
vaso scan --host deploy@10.0.0.5 --ssh-key ~/.ssh/prod_key

# Scan with a custom port
vaso scan --host deploy@host:2222

# Multiple hosts in parallel
vaso scan --host root@host1 --host root@host2 --host root@host3
```

### Password authentication

VASO supports password-based SSH authentication. It establishes a single ControlMaster connection with full terminal access, prompting for the password once. All subsequent operations (file transfer, probe execution, cleanup) reuse that authenticated connection without re-prompting.

```bash
vaso scan --host conde@192.168.1.52
# conde@192.168.1.52's password: ********
# (scans proceed with no further prompts)
```

Key-based authentication works without any prompts if the key is in your SSH agent or specified with `--ssh-key`.

### Privilege escalation

The probe adapts its scan surface based on the privilege level it runs with.

**As root** — scans all user home directories:
```bash
vaso scan --host root@host
# Scans: /root, /home/alice, /home/bob, ...
```

**As regular user** — scans only the current user's home:
```bash
vaso scan --host deploy@host
# Scans: /home/deploy only
# Warning: limited scan — running as "deploy" (no root access)
```

**With sudo escalation** — the probe attempts `sudo` on the remote host:
```bash
vaso scan --host deploy@host --sudo
# If passwordless sudo is available: re-executes as root, scans all users
# If sudo requires a password: falls back to user-only scan with a warning
```

### SSH options

| Flag | Description | Default |
|------|-------------|---------|
| `--host <user@host[:port]>` | Remote target (repeatable) | — |
| `--ssh-key <path>` | SSH identity file | System default |
| `--ssh-timeout <seconds>` | Connection timeout | 60 |
| `--sudo` | Attempt sudo escalation on remote | false |

VASO respects your `~/.ssh/config` for host aliases, jump hosts, and custom settings.

### How it works

1. **Authenticate** — establishes an SSH ControlMaster connection (password/key prompt happens here, once)
2. **Detect platform** — runs `uname -s && uname -m` to identify OS and architecture
3. **Push probe** — SCPs the correct `vaso-probe` binary and a collection manifest to `/tmp/`
4. **Execute** — runs the probe remotely; it collects config files, directory listings, command outputs, and environment variables
5. **Analyze** — parses the probe's JSON output and runs all checks locally
6. **Clean up** — removes the probe binary and manifest from the remote host

Nothing persists on the remote host after the scan.

---

## Inventory-based scanning

For scanning multiple hosts, define them in a YAML inventory file.

### Inventory format

```yaml
hosts:
  - host: 192.168.1.50
    user: root
    label: prod-agent-01

  - host: 192.168.1.51
    user: deploy
    port: 2222
    sudo: true
    label: prod-agent-02

  - host: staging.internal
    user: root
    identity: ~/.ssh/staging_key
    label: staging

  - host: dev.internal
    user: developer
    label: dev-box
```

### Run the scan

```bash
vaso scan --inventory hosts.yaml
vaso scan --inventory hosts.yaml -f json -o fleet-report.json
```

CLI flags override inventory settings:

```bash
# Force sudo on all hosts
vaso scan --inventory hosts.yaml --sudo

# Use a specific key for all hosts
vaso scan --inventory hosts.yaml --ssh-key ~/.ssh/fleet_key
```

### Per-host fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `host` | yes | — | Hostname or IP |
| `user` | no | `root` | SSH username |
| `port` | no | `22` | SSH port |
| `identity` | no | system default | Path to SSH key |
| `sudo` | no | `false` | Attempt sudo escalation |
| `label` | no | `user@host` | Human-readable label in reports |

---

## Snapshot scanning (offline / airgapped)

For hosts with no direct SSH access from the scanner — airgapped systems, restricted networks, or CI pipelines.

### Step 1: Generate a manifest

On the scanner machine:

```bash
vaso probe manifest > manifest.json
```

This produces a JSON file listing every config file, directory, command, and environment variable the scanner needs.

### Step 2: Run the probe on the target

Transfer the probe binary and manifest to the target (USB, SCP, CI artifact, etc.):

```bash
# On the target host (no Node.js needed)
./vaso-probe --manifest manifest.json > snapshot.json

# As root for full multi-user coverage
sudo ./vaso-probe --manifest manifest.json > snapshot.json

# With optional sudo escalation
./vaso-probe --manifest manifest.json --escalate > snapshot.json
```

The probe binary is a static Go executable. It runs on bare Linux and macOS with zero dependencies.

### Step 3: Scan the snapshot

Transfer `snapshot.json` back to the scanner:

```bash
vaso scan --snapshot snapshot.json
vaso scan --snapshot snapshot.json -f sarif -o results.sarif
```

### Validate a snapshot

Check that a snapshot file is well-formed before scanning:

```bash
vaso probe validate snapshot.json
# Snapshot: snapshot.json
#   Host:      srv1437443
#   Platform:  linux
#   Timestamp: 2026-03-20T10:00:00Z
#   Files:     142 collected
#   Dirs:      28 collected
#   Commands:  12 collected
#   Privilege:  root (root)
#   Users:     root, alice, deploy
# Snapshot is valid.
```

---

## Building the probe binaries

The probe must be compiled before remote scanning. Cross-compile for all supported platforms:

```bash
cd probe/
make all
```

This produces 4 static binaries in `probe/dist/`:

| Binary | Platform | Size |
|--------|----------|------|
| `vaso-probe-linux-amd64` | Linux x86_64 | ~2.4 MB |
| `vaso-probe-linux-arm64` | Linux ARM64 | ~2.3 MB |
| `vaso-probe-darwin-amd64` | macOS Intel | ~2.4 MB |
| `vaso-probe-darwin-arm64` | macOS Apple Silicon | ~3.4 MB |

All binaries are statically linked (`CGO_ENABLED=0`) with no runtime dependencies.

The SSH scanning mode automatically selects the correct binary based on the remote host's `uname` output.

---

## Output formats

All scanning modes support the same output formats:

```bash
# Terminal (default)
vaso scan --host root@host

# JSON
vaso scan --host root@host -f json -o report.json

# SARIF (GitHub Code Scanning)
vaso scan --host root@host -f sarif -o results.sarif

# Markdown
vaso scan --host root@host -f markdown -o report.md

# HTML
vaso scan --host root@host -f html -o report.html
```

For multi-host scans, results are displayed per-host with labels:

```
── prod-agent-01 (192.168.1.50) ──
  Agent: openclaw v2.1.0    Score: 72/100 (C)
  ...

── prod-agent-02 (192.168.1.51) ──
  Agent: openclaw v2.1.0    Score: 85/100 (B)
  ...
```

---

## Security considerations

- **Read-only** — the probe only reads files and runs commands. It never modifies anything on the remote host.
- **Command allowlist** — the probe only executes commands from a hardcoded allowlist (netstat, ps, which, agent CLIs, etc.). Arbitrary command execution is not possible.
- **No persistence** — the probe binary and manifest are deleted from the remote host after the scan completes.
- **No callbacks** — the probe never initiates network connections. Data flows one direction: scanner pulls.
- **Sudo is explicit** — `--sudo` / `--escalate` must be explicitly passed. The probe never silently escalates privileges.
- **Snapshot sensitivity** — snapshot files contain config file contents which may include API keys. Handle them like credentials: encrypt at rest, don't commit to version control.

---

## Troubleshooting

### SSH connection fails

```
Permission denied (publickey,password)
```

Verify you can SSH manually first: `ssh user@host`. If that works, VASO will too.

### Unsupported platform

```
Unsupported platform on host: freebsd/amd64
```

The probe supports Linux and macOS only. Use the snapshot workflow: run the probe manually on the host and transfer the snapshot.

### Probe binary not found

```
ENOENT: no such file or directory, 'probe/dist/vaso-probe-linux-amd64'
```

Build the probe binaries first: `cd probe && make all`.

### Limited scan coverage warning

```
Warning: snapshot collected as non-root user "deploy" — scan coverage may be limited.
```

The probe only scanned one user's home directory. For full coverage, connect as root or use `--sudo`.
