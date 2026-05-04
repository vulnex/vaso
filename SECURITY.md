# Security Policy

VASO is a security tool. We take vulnerability reports against VASO itself seriously and ask reporters to follow the coordinated-disclosure process below.

## Supported Versions

Security fixes land on the latest released minor version. Older versions do not receive backports.

| Version | Supported |
|---------|-----------|
| 0.4.x   | Yes       |
| < 0.4   | No        |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.** Use one of the private channels below.

**Preferred — GitHub Private Security Advisory:**
[github.com/vulnex/vaso/security/advisories/new](https://github.com/vulnex/vaso/security/advisories/new)

**Alternative — Email:** security@vulnex.com

Please include:

- A description of the issue and its impact
- Steps to reproduce (proof-of-concept welcome)
- The VASO version affected (`vaso --version`)
- Your platform and Node.js version
- Whether you intend to disclose publicly, and on what timeline

## What to Expect

- **Acknowledgement** within 3 business days of report.
- **Initial assessment** (severity, scope, fix path) within 7 business days.
- **Fix and release** target: 30 days for critical/high, 90 days for medium/low. We will keep you informed if a fix needs longer.
- **Disclosure** is coordinated — we credit the reporter in the release notes unless you ask otherwise, and we will not publish details until a patched release is available.

We do not run a paid bug bounty program at this time.

## Scope

In scope:

- Code execution, privilege escalation, or sandbox escape via VASO itself
- Plugin loading vulnerabilities (`~/.vaso/plugins/`) that could be exploited by a non-privileged user
- IOC feed verification bypass (Ed25519 signature, version monotonicity)
- Memory-safety or DoS issues in scanned-config parsers (YAML / JSON / TOML / JSONC) that crash VASO or exfiltrate data
- Path traversal or unsafe file operations during scan or remediation
- Output-format injection (HTML XSS, SARIF/JSON malformation, CSV formula injection) when scanning attacker-controlled configs
- Credentials or secrets leaking from VASO into reports, logs, or backup files

Out of scope:

- False positives or false negatives in security checks — please open a regular issue.
- Vulnerabilities in the AI agents that VASO scans (report those upstream to the agent's maintainer; VASO can detect and warn about them, but is not the right venue to fix them).
- Vulnerabilities in third-party MCP servers — report upstream to the server's maintainer.
- Issues that require an attacker to already have write access to the user's home directory or VASO config files.
- Social-engineering attacks against VASO maintainers.

## Hardening Stance

VASO is built defense-first:

- **No execution of scanned code.** All analysis is static (Babel AST, regex, entropy). Removing this property would be a regression.
- **No outbound network calls during scans.** Only `vaso update` reaches the network, and only to fetch signed IOC feeds.
- **Bundled, signed IOC feeds.** Remote feeds are verified with a pinned Ed25519 key and rejected on version rollback.
- **No data exfiltration.** Scan results stay local unless the user explicitly redirects them.

If a contribution would weaken any of the above, expect it to be declined regardless of feature value.
