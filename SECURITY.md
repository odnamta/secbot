# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.8.x   | Yes       |
| < 0.8.0 | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in secbot, please report it responsibly through one of the following channels:

- **Email:** dio@atmando.com (preferred for sensitive issues)
- **GitHub Security Advisories:** [https://github.com/odnamta/secbot/security/advisories](https://github.com/odnamta/secbot/security/advisories)

Do **not** open a public GitHub issue for security vulnerabilities.

## What Qualifies as a Vulnerability

Because secbot is itself a security scanning tool, the following are considered in-scope vulnerabilities:

- **Tool exploitability** -- secbot itself can be compromised or used as an attack vector against the user's system.
- **Prompt injection in the AI pipeline** -- malicious input or scan targets can manipulate the AI analysis to produce false results, execute unintended actions, or exfiltrate data.
- **Credential leakage** -- API keys, tokens, or other secrets are exposed in logs, reports, error messages, or network traffic.
- **Scope bypass** -- secbot scans or interacts with targets outside the user-specified scope.
- **Arbitrary code execution** -- untrusted input causes code execution on the machine running secbot.
- **Dependency vulnerabilities** -- a direct dependency introduces a known, exploitable vulnerability.

Out of scope: vulnerabilities found *by* secbot in third-party targets (those should be reported to the respective target owners).

## Response Timeline

secbot is maintained by a solo developer. The following timelines are best-effort commitments:

| Stage | Timeline |
|-------|----------|
| Acknowledgment of report | Within 72 hours |
| Initial assessment and severity classification | Within 7 days |
| Fix for critical/high severity issues | Within 30 days |
| Fix for medium/low severity issues | Within 60 days |

You will be kept informed of progress. If a fix requires more time, an explanation and revised timeline will be provided.

## Responsible Disclosure

We ask that you:

1. Allow reasonable time for the vulnerability to be addressed before public disclosure.
2. Make a good faith effort to avoid privacy violations, data destruction, or disruption of service during your research.
3. Do not use the vulnerability for purposes beyond demonstrating the security issue.

We are committed to working with security researchers and will credit reporters (with permission) in the changelog and release notes once a fix is published.

## Scope of This Policy

This policy applies to the secbot CLI tool and its published npm package. It does not cover third-party services or APIs that secbot integrates with.
