# Security Policy for EnvGuard

## Our Security Commitments

EnvGuard is designed as a developer-side security boundary and secret detection engine. As such, security, privacy, and integrity are foundational to our architecture:

1. **Zero Data Exfiltration Guarantee**:
   EnvGuard is strictly local-first and offline. It performs no remote network calls, has no background analytics or telemetry, and never sends file contents or secret keys outside your workstation or CI runner.

2. **Deterministic Secret Masking**:
   Any discovered secret is masked in memory and display by default. Raw secrets are never printed to terminal logs, standard output, or unencrypted report files unless explicitly requested.

3. **Safe Remediation Pipeline**:
   Remediation via envguard fix --apply isolates extracted secrets into local .env files and guarantees that .env is listed in .gitignore to prevent accidental commits.

---

## Reporting a Vulnerability

If you discover a security vulnerability within EnvGuard itself, please report it responsibly:
- **Do NOT open a public issue or discussion** on GitHub.
- Email your report directly to the security maintainers or contact repository administrators directly via private GitHub Security Advisories.
- Please include description, proof-of-concept, and affected version.
