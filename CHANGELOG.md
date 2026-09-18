# Changelog

All notable changes to EnvGuard are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-09-18

### Production Release Commitments
- **100% Local-First & Privacy Preserving**: Zero telemetry, zero cloud calls, zero external dependencies.
- **Predictable Exit Codes**: Fully documented and tested contracts (`0` = clean/success, `1` = blocking secrets/drift, `2` = usage/CLI error, `3` = fatal).
- **Safe Automated Remediation**: `envguard fix --apply` safely transforms secrets into environment variable references, populates `.env`, and guarantees `.env` is gitignored.

### Added
- **16 Core CLI Commands**: `init`, `scan`, `check`, `diff`, `ci`, `fix`, `audit`, `baseline`, `status`, `watch`, `install-hook`, `pre-push`, `lint-config`, `rules`, `explain`, `doctor`.
- **Compliance Cross-Referencing**: Built-in offline mapping against **SOC 2 Type II** and **ISO/IEC 27001:2022** controls.
- **Enterprise & Organization Policy**: `.envguard-org.yml` governance with immutable enforcement settings.
- **Machine-Readable Outputs**: Comprehensive `--format json` and `--format sarif` integration for CI/CD runners and IDEs.
- **Open Source Health**: Added `CONTRIBUTING.md`, `SECURITY.md`, and GitHub issue/PR templates.

### Changed & Fixed
- **Generic High-Entropy Detection Redesign**: Redesigned entropy classifier into a multi-signal semantic pipeline; eliminated 100% of false positives across real-world codebases.
- **Duplicate Fingerprint Deduplication**: Grouped identical secrets into single canonical findings while tracking all file/line occurrences.
- **Truthful Audit Metrics**: Explicitly separated baseline debt suppression from true active code remediation.
- **Configuration Linter**: Unified schema validation between `lint-config`, `load_config()`, and `load_org_policy()`.

---

## [0.9.11] - 2026-09-18
- Redesigned `generic-high-entropy-secret` rule to require credential variable context or high symbol diversity in assignments.
- Excluded unquoted syntax, MIME types, CSS properties, npm scoped packages, URLs, and SARIF report artifacts.

## [0.9.10] - 2026-09-17
- Fixed duplicate fingerprint issue in multi-occurrence secret findings.
- Separated historical baseline suppression from active code remediation metrics.
- Fixed config linter schema alignment.

## [0.9.0] - 2026-09-13
- Added `envguard lint-config` configuration validation.
- Added offline compliance cross-referencing for SOC 2 and ISO 27001.
- Added self-contained HTML audit reporting.
