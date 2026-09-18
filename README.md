<div align="center">

# EnvGuard

**A lightweight, developer-side safety gate for secrets and environment drift.**

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/badge/version-1.0.0-indigo.svg)](https://github.com/neil-data/envGUARD/releases)
[![Local Only](https://img.shields.io/badge/privacy-100%25%20local-success.svg)](#privacy-and-local-guarantees)
[![Tests](https://img.shields.io/badge/tests-passed-brightgreen.svg)](#testing)

<p>
  <a href="#why-envguard">Why EnvGuard</a> ·
  <a href="#key-features">Key Features</a> ·
  <a href="#installation">Installation</a> ·
  <a href="#cli-commands">CLI Commands</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#organization-policy-envguard-orgyml">Organization Policy</a> ·
  <a href="#automated-remediation--secrets-manager-integration-v080">Remediation</a> ·
  <a href="#rich-terminal-ui-overhaul-v075">Rich Terminal UI</a> ·
  <a href="#developer-workflow-integration-v070">Developer Workflows</a> ·
  <a href="#cicd-integration">CI/CD</a> ·
  <a href="#project-history">Project History</a> ·
  <a href="#roadmap">Roadmap</a> ·
  <a href="#contributing">Contributing</a>
</p>

</div>

---

## Why EnvGuard

Secret leaks into Git are one of the most common, preventable security incidents in software development — a misconfigured `.gitignore`, a key pasted into a tracked file, or a commit made before anyone double-checks what's staged. Existing scanners such as Gitleaks and TruffleHog are excellent, but they're built for CI pipelines and security teams, not the moment right before a developer runs `git commit` or `git push`.

EnvGuard fills that gap: a single lightweight CLI, installed in seconds, that catches secrets before they ever leave your machine — and, uniquely, keeps `.env` and `.env.example` in sync so a team never loses time to a missing environment variable. It runs entirely locally, works the same way across pre-commit, pre-push, CI pipelines, and multi-repo team workflows, and now, as of v1.0.0, can safely remediate what it finds — not just report it.

For the full story of how EnvGuard grew from a local secret scanner into a complete developer-security workflow, see [Project History](#project-history) below.

---

## Privacy and Local Guarantees

> EnvGuard scans repository contents locally and never uploads source code or detected secrets.

| Guarantee | Status |
|---|:---:|
| Cloud backend required | No |
| API keys required | No |
| Repository contents uploaded | No |
| Detected secrets transmitted | No |
| Telemetry by default | No |

All secret detection, line-by-line streaming, SHA-256 baseline fingerprinting, and organization policy evaluations run entirely in local memory on your machine or CI runner.

---

## Key Features

| Feature | Description |
|---|---|
| **Compliance & Audit Reporting** (`v0.9.0`) | Dedicated `envguard audit` command producing executive security posture grades (`A+` to `F`), SOC 2 Type II (CC6.1, CC6.6, CC6.7) and ISO/IEC 27001 (A.5.15, A.8.12, A.8.24) control cross-references, baseline trend tracking, and self-contained print-ready HTML & JSON reports with strict masking guarantees. |
| **Configuration Assurance Linter** (`v0.9.0`) | Dedicated `envguard lint-config` command validating field types, allowed values, typo'd keys, catalog rule IDs, conflicting settings, organization policy overrides, and Git `.env` tracking risks before scans run. |
| **Historical Trend Engine** (`v0.9.0`) | Compares active scan findings against `.envguard-baseline.json` snapshots to quantify newly introduced drift, resolved secrets, persistent legacy debt, and net velocity rates without any external databases. |
| **Automated Remediation** (`v0.8.0`) | Safe, AST-verified remediation (`envguard fix`) for Python source files. Rewrites assignments to `os.environ.get()`, safely adds missing imports, populates `.env` while preserving placeholders in `.env.example`, requires clean git working trees, and defaults strictly to dry-run previews. |
| **Secrets Manager Recognition** (`v0.8.0`) | 100% offline pattern recognition for AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, Google Cloud Secret Manager, and environment lookups — skipping valid secrets manager references without network or cloud calls. |
| **Rich Terminal UI Overhaul** (`v0.7.5`) | Centralized theme system (`envguard/ui/theme.py`), interactive scan progress bars, real-time live monitoring dashboard in `envguard watch`, syntax-highlighted code snippets with strict pre-highlight secret masking, and clean Rich tracebacks for unexpected errors only. |
| **Developer Workflow Integration** (`v0.7.0`) | Git pre-push hook (`envguard install-hook --type pre-push`) with full protocol conformance and ref-injection defenses; zero-dependency filesystem watch mode (`envguard watch`) with debounced scans; and editor-compatible IDE JSON format (`envguard scan --format ide`) with 1-based ranges. |
| **Team & Multi-Repo Workflows** (`v0.6.0`) | Organization security floor (`.envguard-org.yml`), multi-repo scanning (`envguard scan --repos`), clear blocker attribution (`organization policy` vs `local policy`), tolerant error isolation, and CLI injection protection. |
| **CI/CD & GitHub Ecosystem** (`v0.5.0`) | Dedicated `envguard ci` command, environment detection (GitHub Actions, GitLab CI, CircleCI, Azure Pipelines, Jenkins), changed-file diff scanning (`--changed`, `--base`), SARIF 2.1.0 generation, GitHub Actions annotations, and job summaries. |
| **Advanced Detection Engine** (`v0.4.0`) | Multi-signal detection combining known patterns, Shannon entropy analysis, structural JWT validation, and context heuristics. |
| **Pre-Commit Gate** (`envguard check`) | Inspects only staged Git index content (`git show :path`), blocking risky commits before credentials touch Git history. |
| **Directory Scanner** (`envguard scan`) | Line-by-line streaming scan with changed-file support (`--changed`, `--base`), multi-repo support (`--repos`), file output (`--output`), respecting `.gitignore`, `.envguardignore`, and configuration exclusions. |
| **Environment Drift Gate** (`envguard diff`) | Compares `.env` against `.env.example` by key only, flagging missing or stale variables without ever reading secret values. |
| **Security Dashboard** (`envguard status`) | Severity-aware health check covering `.env` Git-tracking risk, credential leaks, organization policy enforcement, baseline status, and hook status. |
| **Cryptographic Baseline** (`envguard baseline create`) | Suppresses existing legacy findings via SHA-256 fingerprints. Adopt EnvGuard on an old codebase without blocking current work. Never writes plaintext secrets to disk. |
| **Interactive Console** (`envguard menu` / `envguard ui`) | A built-in Rich dashboard, plus a dedicated Windows Terminal / Command Prompt launcher with a sandboxed demo mode. |
| **Strict Secret Masking** | Full secrets are never printed in terminal output, JSON, SARIF, or annotations (e.g. `AKIA••••••••••••MPLE`). Immediate hashing prevents plaintext in memory. |
| **Zero Telemetry & 100% Local** | Runs completely on your machine or CI runner. No cloud calls, no external API keys, zero network telemetry. |

---

## Installation

**Option 1 — From wheel**
```bash
pip install dist/envguard-1.0.0-py3-none-any.whl
```

**Option 2 — Editable / developer mode**
```bash
git clone https://github.com/neil-data/envGUARD.git
cd envGUARD
pip install -e .
```

Verify the install:
```bash
envguard --version
# EnvGuard version 1.0.0
```

Works identically in cmd, PowerShell, and Unix shells.

---

## CLI Commands

### 1. `envguard check`
Scans **only staged Git content** directly from the Git index.
```bash
envguard check
envguard check --format json
```
`HIGH` and `MEDIUM` severity findings block the commit (exit code `1`). `LOW` severity findings warn without blocking (exit code `0`).

#### Blocked Commit Screen
```text
┌──────────────────────────────────────────────────────────┐
│                 ENVGUARD BLOCKED COMMIT                  │
│ Blocking security findings were detected in staged units │
│            HIGH: 1          MEDIUM: 1                    │
└──────────────────────────────────────────────────────────┘

                  Blocking Staged Findings
┌──────────┬────────────────────┬─────────────┬──────┬───────────────────────┐
│ Severity │ Rule ID            │ File        │ Line │ Masked Value          │
├──────────┼────────────────────┼─────────────┼──────┼───────────────────────┤
│   HIGH   │ aws-access-key     │ config.py   │   24 │ AKIA••••••••••••MPLE  │
│  MEDIUM  │ api-key-assignment │ settings.py │   18 │ sk_live_••••••••      │
└──────────┴────────────────────┴─────────────┴──────┴───────────────────────┘

┌──────────────────────────── Next Steps ────────────────────────────┐
│ 1. Remove sensitive credentials from staged files.                 │
│ 2. Store credentials using secure environment configuration.       │
│ 3. Rotate credentials if a real secret was exposed.                │
│ 4. Stage the corrected files and try again.                        │
└────────────────────────────────────────────────────────────────────┘
```

---

### 2. `envguard scan`
Recursively scans the working directory or specific files for secrets with real-time feedback.
```bash
# Scan full working directory
envguard scan

# Scan specific path (positional or flag)
envguard scan src/
envguard scan --path ./src

# Scan only changed files relative to base branch
envguard scan --changed
envguard scan --changed --base origin/main

# Multi-repository scanning
envguard scan --repos ./backend,./frontend,./microservice-a
envguard scan --repos ./backend --repos ./frontend --format json

# Output formats: text, json, sarif, or ide
envguard scan --format json
envguard scan --format ide
envguard scan --format sarif --output results.sarif
envguard scan --verbose
```

#### Scan Complete Output
```text
┌───────────── Scan Complete ─────────────┐
│ Files scanned: 124                      │
│ Files skipped: 8                        │
│ Findings: 2                             │
└─────────────────────────────────────────┘

                      Detected Secrets
┌──────────┬────────────────────┬─────────────┬──────┬───────────────────────┐
│ Severity │ Rule ID            │ File        │ Line │ Masked Value          │
├──────────┼────────────────────┼─────────────┼──────┼───────────────────────┤
│   HIGH   │ aws-access-key     │ config.py   │   24 │ AKIA••••••••••••MPLE  │
│  MEDIUM  │ api-key-assignment │ settings.py │   18 │ sk_live_••••••••      │
└──────────┴────────────────────┴─────────────┴──────┴───────────────────────┘

Breakdown: 1 HIGH  •  1 MEDIUM  •  0 LOW
```

---

### 3. `envguard ci`
Automated CI/CD security gate designed for pipelines and pull requests.
```bash
# Scan changed files against the default branch (main/master)
envguard ci

# Specify custom base branch or ref
envguard ci --base origin/main

# Full repository scan in CI
envguard ci --all

# Generate SARIF report for GitHub Code Scanning
envguard ci --format sarif --output envguard.sarif

# Standard JSON report
envguard ci --format json --output envguard-report.json
```

**Key CI features:**
- **Auto-environment detection** — recognizes GitHub Actions, GitLab CI, CircleCI, Azure Pipelines, Jenkins, or a generic CI environment.
- **Git diff scanning** — by default, scans only files modified or added between the base branch (`origin/main`, `main`, etc.) and the current commit, keeping CI fast.
- **GitHub Actions integration** — emits native workflow annotations (`::error::` for HIGH/MEDIUM, `::warning::` for LOW) and automatically writes a Markdown security report into `$GITHUB_STEP_SUMMARY`.
- **Baseline awareness** — automatically suppresses known legacy findings using `.envguard-baseline.json` or `--baseline <path>`.
- **Zero plaintext leaks** — masked secrets only; raw secrets are never written to logs, summaries, or SARIF files.
- **Deterministic exit codes:**
  - `0` — pass (no blocking findings)
  - `1` — block (HIGH or MEDIUM findings detected)
  - `2` — runtime / Git error
  - `3` — usage / CLI syntax error

---

### 4. `envguard diff`
Compares environment variable keys between `.env` and `.env.example`.
```bash
envguard diff
envguard diff --env .env.local --example .env.template
```
Flags variables present in `.env` but missing from `.env.example`, and vice versa. Values are never parsed or logged.

#### Drift Report
```text
┌──────────── ENVIRONMENT CONFIGURATION DRIFT ────────────┐
│ .env variables: 12      .env.example variables: 10      │
└─────────────────────────────────────────────────────────┘

┌───────────────────────────┬──────────────────────┐
│ Status                    │ Environment Variable │
├───────────────────────────┼──────────────────────┤
│ Missing from .env.example │ STRIPE_WEBHOOK_KEY    │
│ Missing from .env.example │ SENTRY_DSN            │
├───────────────────────────┼──────────────────────┤
│ Extra in .env.example     │ DEPRECATED_URL        │
└───────────────────────────┴──────────────────────┘
```

---

### 5. `envguard status`
Displays a severity-aware project security dashboard — Git repo status, whether `.env` is accidentally tracked (critical), active findings by severity, `.env.example` sync, configuration, baseline, and hook install status.
```bash
envguard status
```

```text
                  ENVGUARD PROJECT STATUS
┌──────────────────────────┬───────────────────────────────┐
│ Check                    │ Status                        │
├──────────────────────────┼───────────────────────────────┤
│ Git Repository           │ DETECTED                      │
│ Secrets                  │ CLEAN                         │
│ .env Tracked             │ NO                            │
│ .env.example Sync        │ SYNCHRONIZED                  │
│ Pre-Commit Hook          │ INSTALLED                     │
│ Configuration            │ VALID (.envguard.yml)         │
│ Baseline                 │ ACTIVE (3 entries)            │
└──────────────────────────┴───────────────────────────────┘

┌────────────────────────────────────────────────────────┐
│  OVERALL STATUS: SECURE                                │
│  All security checks passed. Repository is protected.  │
└────────────────────────────────────────────────────────┘
```

---

### 6. `envguard install-hook`
Installs or safely appends the EnvGuard safety gate into `.git/hooks/pre-commit` or `.git/hooks/pre-push`.
```bash
# Install pre-commit hook (default)
envguard install-hook
envguard install-hook --type pre-commit

# Install pre-push hook
envguard install-hook --type pre-push
```
- Clear boundary markers (`# BEGIN ENVGUARD HOOK ... # END ENVGUARD HOOK`)
- Preserves existing hooks without overwriting user scripts
- Runs automatically before every commit or outgoing push

---

### 6b. `envguard pre-push`
Scans outgoing commits before pushing to a remote repository. Invoked automatically by Git's `pre-push` hook or manually for pre-flight testing.
```bash
# Manual check of outgoing commits
envguard pre-push origin

# Output machine-readable JSON summary
envguard pre-push origin --format json
```
- Fully implements Git's pre-push protocol (`<local-ref> <local-sha> <remote-ref> <remote-sha>`)
- Resolves commit ranges (`rev-list`) and retrieves file bytes directly from Git objects (`git show <commit>:<path>`)
- Built-in defenses against ref/flag injection attacks

---

### 6c. `envguard watch`
Runs a zero-dependency filesystem watcher that continuously monitors files and triggers debounced scans on save.
```bash
# Watch current working directory
envguard watch

# Watch specific source folder with custom debounce
envguard watch ./src --debounce 0.5
```
- Native `os.scandir` monitoring with zero third-party dependencies
- Automatic event debouncing to prevent scan storms
- Prunes ignored directories (`.git`, `node_modules`, `venv`, etc.) and respects `.gitignore` / `.envguardignore`
- Clean `Ctrl+C` graceful shutdown

---

### 6d. `envguard fix`
Safely remediates hardcoded secrets in Python source and `.env` files.
```bash
# Preview proposed changes (dry-run mode, no files touched)
envguard fix

# Apply changes to source code and sync .env
envguard fix --apply

# Allow running with unstaged changes in working tree
envguard fix --apply --allow-dirty

# Output remediation plan in machine-readable JSON
envguard fix --format json
```
- **Strict Dry-Run Default**: Never writes to disk without `--apply`.
- **Git Cleanliness Gate**: Aborts if uncommitted changes are present (bypass with `--allow-dirty`).
- **AST Verification**: Inspects AST nodes to guarantee simple assignments only; multiline, f-strings, and complex expressions are safely left for manual review.
- **Environment Synchronization**: Moves secrets into `.env` and automatically appends placeholders (`"your-secret-key-here"`) to `.env.example` — plaintext secrets are never written to example files.
- **Safe Import Injection**: Injects `import os` directly after module docstrings or top-level comments if missing.
- **Automatic Git Exclusion**: Ensures `.env` is excluded via `.gitignore` before or immediately after writing it, so a freshly extracted secret is never one `git add .` away from being committed.
- **Offline Secrets Manager Recognition**: Recognizes AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, and GCP Secret Manager lookups without any network calls.

---

### 6e. `envguard lint-config`
Validates EnvGuard configuration files and Git safety controls.
```bash
# Lint current repository configuration and Git safety
envguard lint-config

# Lint specific configuration file or directory
envguard lint-config path/to/project

# Output diagnostics in machine-readable JSON
envguard lint-config --format json --output lint-report.json
```
- **Rigorous Schema Validation**: Validates field types, allowed values, and severity levels using the same core schema as `load_config()`.
- **Typo & Unknown Key Detection**: Flags misspelled or unexpected keys across top-level, `scan`, `rules`, `ci`, and `advanced_detection` sections.
- **Rule ID Verification**: Validates all disabled rules and severity overrides against the EnvGuard pattern catalog.
- **Conflict Analysis**: Catches contradictory configurations, such as rules marked simultaneously as disabled and overridden with a severity.
- **Organization Policy Enforcement**: Validates local configurations against `.envguard-org.yml` security floors, preventing local loosening of org-mandated rules.
- **Git Exposure Protection**: Inspects Git index and `.gitignore` status to ensure `.env` files containing secrets are never staged or tracked.

---

### 6f. `envguard audit`
Generates executive compliance and historical audit reports.
```bash
# Print executive terminal audit summary
envguard audit

# Generate self-contained, print-ready HTML / PDF audit report
envguard audit --format html -o envguard-audit.html

# Generate comprehensive machine-readable JSON report
envguard audit --format json -o envguard-audit.json

# Audit with specific baseline snapshot
envguard audit --baseline custom-baseline.json
```
- **Executive Security Posture Score**: Computes a clear letter grade (`A+` through `F`) evaluating credential findings and configuration health.
- **Compliance Framework Alignment**: Cross-references findings against **SOC 2 Type II** (`CC6.1`, `CC6.6`, `CC6.7`) and **ISO/IEC 27001:2022** (`A.5.15`, `A.8.12`, `A.8.24`) controls.
- **Historical Debt Tracking**: Distinguishes newly introduced drift, genuinely resolved secrets, and findings that remain suppressed in the baseline — a suppressed finding is reported as *persistent legacy debt*, not as proof of remediation.
- **Self-Contained Offline HTML**: Zero external scripts, stylesheets, or CDN fonts. Fully styled with modern dark mode and print-optimized `@media print` rules for instant PDF export.
- **Strict Masking Guarantee**: Plaintext secrets are never rendered into HTML or JSON audit exports.

---

### 7. `envguard baseline create`
Captures all existing repository findings into `.envguard-baseline.json`.
```bash
envguard baseline create
envguard baseline create --overwrite
```
Computes in-memory SHA-256 fingerprints. Subsequent scans suppress baseline findings, allowing adoption on legacy codebases without blocking current work. A baseline suppresses re-reporting of a known finding — it is a record of what's been acknowledged, not evidence that a secret was rotated or removed.

---

### 8. `envguard init`
Initializes starter configuration (`.envguard.yml`) and ignore (`.envguardignore`) files safely without overwriting existing settings.
```bash
envguard init
envguard init --format json
```

---

### 9. `envguard doctor`
Runs comprehensive system diagnostics (Python, Git, rules, configuration, pre-commit hook, ignore setup, baseline validity).
```bash
envguard doctor
envguard doctor --format json
```

---

### 10. `envguard explain` & `envguard rules list`
Inspects built-in rules, explaining why they exist, severity, and remediation guidance.
```bash
envguard explain aws-access-key
envguard rules list
envguard rules list --format json
```

---

### 11. Inline suppressions
Suppress intentional test secrets or fixtures directly in code using standard comment directives:
```python
# Suppress all rules on this line:
api_key = "AKIAIOSFODNN7EXAMPLE"  # envguard: ignore

# Suppress specific rule on this line:
password = "secretpass123"  # envguard: ignore=password-assignment

# Suppress all rules on next line:
# envguard: ignore-next-line
secret_token = "ghp_123456789012345678901234567890123456"

# Suppress specific rule on next line:
# envguard: ignore-next-line=stripe-secret-key
stripe_key = "sk_test_51MockedKeyForTestingPurposes00"
```
Supported comment formats: `#` (Python, Bash, YAML), `//` (JS, TS, Go, Java, C++), `/* ... */`.

---

## Interactive Console

Run `envguard menu` (or simply `envguard`) for the interactive console, or `envguard ui` to open it in a dedicated window:

```text
┌─────────────────────────────────────────────────────────┐
│                        ENVGUARD                         │
│             Developer Security Safety Gate              │
│    Secrets • Git Protection • Environment Validation    │
└─────────────────────────────────────────────────────────┘

Project:         my-project
Path:            C:\Projects\my-project
EnvGuard:        v1.0.0
Git Repository:  Detected

┌─────────── Select an Option ────────────┐
│   [1]    Project Security Status        │
│   [2]    Scan Working Directory         │
│   [3]    Check Staged Git Changes       │
│   [4]    Compare .env vs .env.example   │
│   [5]    Install Pre-Commit Hook        │
│   [6]    Create / Update Baseline       │
│   [7]    Run Safe Secret Leak Demo      │
│   [8]    Initialize Project             │
│   [9]    Run Doctor Diagnostics         │
│   [0]    Exit                           │
└─────────────────────────────────────────┘

Select an option:
```

---

## Configuration

EnvGuard works with zero configuration. To customize rules, size limits, or exclusions, add a `.envguard.yml` to your repository root:

```yaml
# EnvGuard Configuration (.envguard.yml)
version: 1

scan:
  max_file_size_mb: 5.0        # Skip files larger than 5 MB (default)
  block_on:                    # Severities that block commits (HIGH, MEDIUM, LOW)
    - HIGH
    - MEDIUM
  respect_gitignore: true

exclude:                       # Excluded file globs
  - tests/fixtures/**
  - vendor/**

rules:
  disabled:                    # Disable specific rule IDs
    - generic-secret
  severity_overrides:          # Override rule severity
    api-key-assignment: HIGH

placeholders:
  - my_dummy_api_key           # Whitelisted non-secret placeholders
  - test_mock_token

# Advanced Multi-Signal Detection
advanced_detection:
  entropy:
    enabled: true              # Shannon entropy analysis
    min_length: 20             # Minimum token length to analyze (>= 8)
    threshold: 4.0             # Shannon entropy cutoff (bits/char, 1.0 - 8.0)
  jwt:
    enabled: true              # Structural 3-segment Base64URL JWT validation
  context_analysis:
    enabled: true              # Heuristic credential vs metadata context analysis

reporting:
  color: true
  show_fingerprints: false

# CI/CD Configuration
ci:
  changed_files_only: true     # Only scan files changed relative to base ref
  base_branch: null            # Auto-detect default branch (main/master) or specify ref
  annotations: true            # Emit GitHub Actions ::error:: and ::warning:: annotations
  job_summary: true            # Append Markdown summary to $GITHUB_STEP_SUMMARY
```

> **Advanced Detection Engine:** Combines pattern regexes, Shannon entropy calculations, structural JWT header decoding, and surrounding variable context into a centralized multi-signal scoring system. Known regex rules preserve their configured severity by design. UUIDs, Git hashes, SHA-256 digests, version numbers, file paths, and placeholders are excluded to minimize false positives. Configuration supports strict boundary validation on all fields — run `envguard lint-config` at any time to check `.envguard.yml` against the current schema before relying on it.

---

## Organization Policy (`.envguard-org.yml`)

EnvGuard supports `.envguard-org.yml` (or `.envguard-org.yaml`) committed alongside `.envguard.yml`.

### Hybrid Policy Model & Fail-Stop Security Floor
The organization policy establishes a non-negotiable **security floor** that individual developer or local configurations cannot weaken:

1. **Unbreakable `block_on` Floor**: If `.envguard-org.yml` mandates blocking on `HIGH`, a local `.envguard.yml` cannot omit `HIGH`. Local policies may strengthen enforcement (e.g. adding `MEDIUM` or `LOW`), but any attempt to weaken it raises a `ConfigurationError` and immediately halts execution.
2. **Rule Disabling Protection**: Local configuration cannot disable any rule that is actively enforced by organization policy.
3. **Severity Override Floor**: Local configuration cannot downgrade a severity override below what organization policy specifies.
4. **Transparent Attribution**: Findings report exactly which policy triggered blocking:
   - `Blocked by: organization policy`
   - `Blocked by: local policy`
   - `Blocked by: organization & local policy`
5. **Integrated Auditing**: Both `envguard status` and `envguard doctor` automatically detect, validate, and report organization policy status.

---

## Stable Rule IDs

| Rule ID | Rule Name | Default Severity | Target / Pattern |
|---|---|:---:|---|
| `aws-access-key` | AWS Access Key | HIGH | AWS Access Key ID (`AKIA...`) |
| `aws-secret-access-key` | AWS Secret Access Key | HIGH | AWS secret access key (40-character Base64 value) |
| `aws-session-token` | AWS Session Token | HIGH | AWS temporary session token assignment |
| `google-api-key` | Google API Key | MEDIUM | Google Cloud Platform API keys (`AIza...`) |
| `google-service-account-key` | Google Service Account Key | HIGH | Google Cloud service account JSON key file indicator |
| `azure-storage-connection-string` | Azure Storage Connection String | HIGH | Azure storage connection strings with access keys |
| `azure-storage-key` | Azure Storage Account Key | HIGH | Azure storage account key (86-88 char Base64) |
| `github-token` | GitHub Personal Access Token | HIGH | Classic `ghp_` or fine-grained `github_pat_` |
| `gitlab-token` | GitLab Personal Access Token | HIGH | GitLab personal or project tokens (`glpat-...`) |
| `npm-token` | npm Access Token | HIGH | npm access tokens (`npm_...`) or registry auth tokens |
| `pypi-token` | PyPI API Token | HIGH | PyPI package index API tokens (`pypi-...`) |
| `stripe-secret-key` | Stripe Secret Key | HIGH | Stripe API keys (`sk_*`, `rk_*`) |
| `slack-token` | Slack Token | HIGH | Slack bot, app, or user tokens (`xoxb-...`) |
| `discord-token` | Discord Bot Token | MEDIUM | Discord bot or webhook token assignment |
| `jwt-token` | JSON Web Token (JWT) | HIGH | Structural 3-segment Base64URL JWT verification |
| `generic-high-entropy-secret` | High Entropy Secret | MEDIUM | Shannon entropy analysis in credential context, with multi-signal false-positive filtering |
| `pem-private-key` | Private Key | HIGH | OpenSSL / PEM private key header |
| `api-key-assignment` | API Key Assignment | MEDIUM | Assignments containing `API_KEY` |
| `secret-assignment` | Secret Assignment | MEDIUM | Assignments containing `SECRET` |
| `secret-key-assignment` | Secret Key Assignment | MEDIUM | Assignments containing `SECRET_KEY` |
| `password-assignment` | Password Assignment | MEDIUM | Assignments containing `PASSWORD` |
| `db-password-assignment` | Database Password | MEDIUM | Assignments containing `DB_PASSWORD` |
| `token-assignment` | Token Assignment | MEDIUM | Assignments containing `TOKEN` |
| `generic-credential` | Generic Credential | LOW | Assignments containing `credential` |
| `generic-secret` | Generic Secret | LOW | Assignments containing `key` |

---

## Exit Code Contract

| Exit Code | Meaning | Example |
|:---:|---|---|
| `0` | Success / clean | No blocking findings, files in sync, or warnings only |
| `1` | Blocking findings | Staged HIGH/MEDIUM secrets, or unsuppressed scan findings |
| `2` | Runtime / config error | Invalid `.envguard.yml`, missing required file, Git error |
| `3` | Invalid CLI usage | Unknown flags, missing required arguments, bad options |

---

## Automated Remediation & Secrets Manager Integration (v0.8.0)

EnvGuard's first write-capable release, built around **safety over automation**:

### Safe, Reversible Code Remediation (`envguard fix`)

- **Strict Dry-Run Default**: By default, `envguard fix` runs in preview mode without touching any files. Passing `--apply` is strictly required to write changes to disk.
- **Git Working Tree Cleanliness**: Refuses to run if uncommitted Git changes exist, preventing accidental modification of dirty states (overridable with `--allow-dirty`).
- **AST-Verified Safety Gate**: Uses Python's abstract syntax tree (`ast`) to ensure only simple, unambiguous assignments are rewritten. Unsafe constructs (multiline values, dict literals, f-strings, complex function calls) are safely flagged as requiring manual remediation.
- **Environment Synchronization**: Extracted secrets are appended to `.env` if not already present. Concurrently, a placeholder entry is appended to `.env.example` — guaranteeing plaintext secrets are never written to version-controlled example files.
- **Safe Import Injection**: Injects `import os` directly after module-level docstrings and initial comments if not already imported.
- **Automatic `.gitignore` Protection**: Ensures `.env` is excluded from Git before leaving a real secret sitting in an untracked, unprotected file.
- **Fail-Safe Atomic Writes**: Modifications use atomic write operations with complete in-memory rollback if any file operation fails.

### Secrets Manager Offline Recognition

EnvGuard recognizes enterprise secrets manager patterns and environment lookups 100% offline with zero cloud SDK calls, zero API credentials, and zero network calls:
- **AWS Secrets Manager**: `boto3.client("secretsmanager")`, `get_secret_value`
- **HashiCorp Vault**: `hvac.Client`, `client.secrets.kv`, `vault.read`
- **Azure Key Vault**: `azure.keyvault.secrets`, `SecretClient`, `get_secret`
- **Google Cloud Secret Manager**: `google.cloud.secretmanager`, `SecretManagerServiceClient`, `access_secret_version`
- **Environment Lookups**: `os.environ.get`, `os.getenv`, `os.environ[...]`

Valid secrets manager lookups are recognized and skipped during remediation.

---

## Rich Terminal UI Overhaul (v0.7.5)

A full terminal UI overhaul built on Rich, while keeping all underlying detection, Git handling, and output contracts untouched:

- **Centralized UI Theme (`envguard.ui.theme`)**: Single source of truth for severity badges (`HIGH`, `MEDIUM`, `LOW`), status badges (`PASS`, `WARNING`, `ERROR`, `BLOCKED`, `CLEAN`, `CRITICAL`), standardized panels, and tables — used consistently by every command.
- **Interactive Scan Progress**: Responsive progress tracking in interactive terminal sessions, automatically and strictly suppressed in CI environments, non-TTY outputs, and machine-readable formats (`--format json`, `--format sarif`, `--format ide`).
- **Watch Live Monitoring Dashboard**: `envguard watch` renders a live status panel showing directory, tracked file count, status, last checked time, and recent activity, with graceful `Ctrl+C` exit and no tracebacks.
- **Syntax Highlighting with Pre-Masking Security**: Code snippets render with syntax highlighting. Plaintext secrets are strictly masked *prior* to reaching the syntax highlighter, guaranteeing raw secrets never leak into rendered output.
- **Clean Exception Handling**: Known configuration, Git, and scanning errors are presented in clear panels, while genuinely unexpected exceptions are formatted via a readable Rich traceback rather than a raw Python stack dump.

---

## Developer Workflow Integration (v0.7.0)

Secret detection integrated directly into active developer workflows — catching leaks earlier and avoiding post-push secret exposure incidents.

### Production Git Pre-Push Hook

While pre-commit catches uncommitted staged secrets, the **pre-push hook** serves as the definitive perimeter defense before commits leave the developer's machine and propagate to remotes.

- **Full Git Protocol Compliance**: Intercepts Git's stdin stream (`<local-ref> <local-sha> <remote-ref> <remote-sha>`) across single or multiple ref pushes.
- **Deep Commit Range Resolution**: Accurately computes commit ranges for branch updates, new branches/tags, and gracefully skips deletions.
- **True Git Object Inspection**: Scans files directly from Git's object store using `git diff-tree` and `git show <commit>:<path>`, catching intermediate leaks in commit chains even if undone in subsequent commits.
- **Strict Injection Defenses**: Rejects any ref or SHA starting with `-` or containing null bytes, and terminates commands with `--`.
- **Idempotent Installation**: `envguard install-hook --type pre-push`

### Zero-Dependency Filesystem Watcher

Continuous monitoring detects secrets the moment files are saved to disk — without leaving the terminal:

- **100% Python Standard Library**: Runs using native `os.scandir` and filesystem `mtime_ns` / `size` caching with **zero third-party dependencies**.
- **Debounced Event Processing**: Configurable debounce interval (default `0.3s`) prevents scan storms and duplicate alerts during rapid saves.
- **Intelligent Pruning**: Automatically prunes `.git`, `node_modules`, `venv`, `build`, `dist`, `__pycache__`, and respects `.gitignore` and `.envguardignore`.
- **Single Detection Engine**: Reuses the core streaming engine for identical detection accuracy across all commands.

### Editor & IDE Diagnostic JSON (`--format ide`)

A versioned diagnostic schema (`schema_version: 1`) engineered for IDE extensions, Language Server Protocol (LSP) daemons, and editor diagnostics (VS Code, JetBrains, Neovim):

- **1-Based Character Coordinates**: Every finding includes deterministic `line`, `column`, `end_line`, and `end_column` properties, with safe fallback coordinates (`min: 1`).
- **Guaranteed Privacy**: Plaintext secrets are strictly masked (`masked_value`) and never exposed in the JSON output.

```bash
envguard scan --format ide
envguard ci --format ide
```

```json
{
  "schema_version": 1,
  "tool": "envguard",
  "version": "1.0.0",
  "status": "failed",
  "total_findings": 1,
  "findings": [
    {
      "file": "src/config.py",
      "line": 12,
      "column": 11,
      "end_line": 12,
      "end_column": 31,
      "severity": "HIGH",
      "rule_id": "aws-access-key",
      "rule_name": "AWS Access Key",
      "message": "Secret detected (AWS Access Key)",
      "fingerprint": "sha256:...",
      "masked_value": "AKIA••••••••••••MPLE",
      "blocked_by": "local policy"
    }
  ]
}
```

---

## CI/CD Integration

EnvGuard is built from the ground up for continuous integration pipelines, automated pull request validation, and GitHub Code Scanning.

### GitHub Actions workflow

EnvGuard includes a ready-to-use GitHub Actions workflow template at [`.github/workflows/envguard.yml`](.github/workflows/envguard.yml):

```yaml
name: EnvGuard Security Gate

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

permissions:
  contents: read
  security-events: write

jobs:
  security-scan:
    name: Secret & Drift Gate
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history so Git can compare against the base branch

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install EnvGuard
        run: pip install .

      - name: Run EnvGuard CI Gate
        run: envguard ci --format sarif --output envguard.sarif

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: envguard.sarif
```

### GitHub Actions native features

When running inside GitHub Actions (`GITHUB_ACTIONS=true`), EnvGuard automatically:

1. **Emits workflow annotations**
   - `::error file={path},line={line},title={rule_name}::[EnvGuard] {description}`
   - `::warning file={path},line={line},title={rule_name}::[EnvGuard] {description}`
   - LOW-severity findings are recorded in SARIF output (mapped to `note` level) but do not emit annotations by default, to avoid noise on pull requests.
2. **Generates rich job summaries** — writes a clean, high-level summary table and severity breakdown to `$GITHUB_STEP_SUMMARY`, visible directly on the Actions job page.
3. **Protects credentials** — only masked secret tokens (e.g. `AKIA••••••••••••MPLE`) are ever written to stdout, SARIF, or `$GITHUB_STEP_SUMMARY`.

### SARIF severity mapping

| EnvGuard Severity | SARIF Level |
|:---:|:---:|
| HIGH | `error` |
| MEDIUM | `warning` |
| LOW | `note` |

### Other CI environments

EnvGuard auto-detects and runs seamlessly inside **GitLab CI**, **CircleCI**, **Azure Pipelines**, and **Jenkins**. It automatically compares changed files against the default branch without any extra configuration needed.

---

## Testing

```bash
pytest -v
```

Run the full suite from the EnvGuard repository root before relying on any reported pass count — a project this size is worth verifying directly rather than trusting a number in documentation.

---

## Project History

EnvGuard began as a focused, 5-hour MVP: a CLI that scanned staged files for obvious secret patterns before a commit. It grew through a deliberate cycle repeated across every major release — ship a feature, verify it live against real projects (not just the test suite), fix what's actually broken, and only then move to the next milestone.

That process has included two genuine security findings worth being upfront about: an arbitrary file-write vulnerability via Git reference argument injection, and a CI blocking bypass caused by unvalidated configuration values — both found through direct live testing rather than automated scanning, and both fixed and independently re-verified before the next release shipped. The full version-by-version history is in the [Roadmap](#roadmap) below.

By v1.0.0, EnvGuard covers the full lifecycle: catch secrets before they're committed or pushed, enforce policy across teams and multiple repositories, integrate into CI/CD and editors, safely remediate what's found, and report on compliance posture over time — all without a network call.

---

## Roadmap

| Version | Milestone | Status |
|---|---|:---:|
| v0.1.0 | MVP | Complete |
| v0.2.0 | Open-source foundation | Complete |
| v0.2.5 | Rich terminal UI upgrade | Complete |
| v0.3.0 | Smart Developer Workflow (ignore, suppressions, doctor, init, explain) | Complete |
| v0.3.1 | Configuration stability & production reliability patch | Complete |
| v0.4.0 | Advanced Detection Engine (entropy, JWT validation, expanded cloud provider rules) | Complete |
| v0.4.2 | Stability & production diagnostics patch | Complete |
| v0.5.0 | CI/CD & GitHub Ecosystem (CI detection, changed-file diff, SARIF 2.1.0, GitHub annotations & step summaries) | Complete |
| v0.5.3 | Bug fix release (baseline consistency, independent entropy rule, output confirmation) | Complete |
| v0.5.4 | Security & consistency patch (ref injection prevention, block_on validation, specificity fix) | Complete |
| v0.5.5 | Micro patch (Rich console stderr fix, status command config warnings surfaced) | Complete |
| v0.6.0 | Team & Multi-Repo Workflows (organization security floor, multi-repo scanning, blocker attribution) | Complete |
| v0.6.6 | Patch (organization policy schema fix, multi-repo scan crash fix) | Complete |
| v0.7.0 | Developer Workflow Integration (Git pre-push hook, filesystem watch mode, IDE diagnostic JSON) | Complete |
| v0.7.5 | Full Rich Terminal UI Overhaul (theme system, progress bars, watch live dashboard, syntax highlighting) | Complete |
| v0.8.0 | Automated Remediation & Secrets Manager Integration (`envguard fix`, AST verification, offline secrets manager recognition) | Complete |
| v0.8.7 | Remediation safety fixes (BOM handling, automatic `.gitignore` exclusion, `.env` scan-scope fix) | Complete |
| v0.9.0 | Compliance & Audit Reporting (`envguard audit`, `lint-config`, SOC 2/ISO 27001 mapping, trends) | Complete |
| v0.9.8–v0.9.11 | Precision & audit accuracy fixes (entropy false-positive reduction, config schema alignment, truthful baseline debt metrics) | Complete |
| **v1.0.0** | **Stable Production Release** | **Current Release** |

---

## Contributing

EnvGuard is now open for outside contribution. Before opening a pull request:

- Read `CONTRIBUTING.md` for the development setup, testing expectations, and a map of the codebase.
- Every change must include regression tests and pass the full existing suite — no exceptions for "small" fixes, since several of this project's most serious bugs were exactly that.
- Changes touching subprocess calls, configuration validation, or path handling get extra scrutiny — see `CONTRIBUTING.md` for the specific patterns to follow, based on real vulnerabilities found and fixed in this project's history.
- Use the issue templates for bug reports (especially false positive/negative detection reports) and feature requests.

---

## License

Distributed under the MIT License. See [`LICENSE`](./LICENSE) for details.
