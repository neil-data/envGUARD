<div align="center">

# EnvGuard

**A lightweight, developer-side safety gate for secrets and environment drift.**

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/badge/version-0.7.0-indigo.svg)](https://github.com/neil-data/envGUARD/releases)
[![Local Only](https://img.shields.io/badge/privacy-100%25%20local-success.svg)](#privacy-and-local-guarantees)
[![Tests](https://img.shields.io/badge/tests-190%20passed-brightgreen.svg)](#testing)


<p>
  <a href="#why-envguard">Why EnvGuard</a> ·
  <a href="#key-features">Key Features</a> ·
  <a href="#developer-workflow-integration">Developer Workflows</a> ·
  <a href="#installation">Installation</a> ·
  <a href="#cli-commands">CLI Commands</a> ·
  <a href="#interactive-console">Interactive Console</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#organization-policy">Organization Policy</a> ·
  <a href="#cicd-integration">CI/CD & GitHub</a> ·
  <a href="#roadmap">Roadmap</a>
</p>

</div>

---

## Why EnvGuard

Secret leaks into Git are one of the most common, preventable security incidents in software development — a misconfigured `.gitignore`, a key pasted into a tracked file, or a commit made before anyone double-checks what's staged. Existing scanners such as Gitleaks and TruffleHog are excellent, but they're built for CI pipelines and security teams, not the moment right before a developer runs `git commit` or `git push`.

EnvGuard fills that gap: a single lightweight CLI, installed in seconds, that catches secrets before they ever leave your machine — and, uniquely, keeps `.env` and `.env.example` in sync so a team never loses time to a missing environment variable. With v0.5.0, that same protection extended into CI/CD pipelines and pull requests. With v0.6.0, team-wide organization policies and multi-repository scanning brought enterprise-grade workflows while maintaining 100% local-first privacy. With v0.7.0, developer workflow integrations — including a native Git pre-push hook, a zero-dependency filesystem watcher, and editor-compatible diagnostic JSON — catch secrets even earlier in active developer workflows.

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
| **Developer Workflow Integration** (`v0.7.0`) | Git pre-push hook (`envguard pre-push`, `envguard install-hook --type pre-push`) with full protocol conformance and ref-injection defenses; zero-dependency filesystem watch mode (`envguard watch`) with debounced scans; and editor-compatible IDE JSON format (`envguard scan --format ide`) with 1-based ranges. |
| **Team & Multi-Repo Workflows** (`v0.6.0`) | Organization security floor (`.envguard-org.yml`), multi-repo scanning (`envguard scan --repos`), clear blocker attribution (`organization policy` vs `local policy`), tolerant error isolation, and CLI injection protection. |
| **CI/CD & GitHub Ecosystem** (`v0.5.0`) | Dedicated `envguard ci` command, environment detection (GitHub Actions, GitLab CI, CircleCI, Azure Pipelines, Jenkins), changed-file diff scanning (`--changed`, `--base`), SARIF 2.1.0 generation, GitHub Actions annotations, and job summaries. |
| **Advanced Detection Engine** (`v0.4.0`) | Multi-signal detection combining known patterns, Shannon entropy ($H \ge 4.0$), structural JWT validation, and context heuristics. |
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
pip install dist/envguard-0.7.0-py3-none-any.whl
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
# EnvGuard version 0.7.0
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

# Multi-repository scanning (new in v0.6.0)
envguard scan --repos ./backend,./frontend,./microservice-a
envguard scan --repos ./backend --repos ./frontend --format json

# Output formats: text, json, sarif, or ide (new in v0.7.0)
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

### 3. `envguard ci` (new in v0.5.0)
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

# Install pre-push hook (new in v0.7.0)
envguard install-hook --type pre-push
```
- Clear boundary markers (`# BEGIN ENVGUARD HOOK ... # END ENVGUARD HOOK`)
- Preserves existing hooks without overwriting user scripts
- Runs automatically before every commit or outgoing push

---

### 6b. `envguard pre-push` (new in v0.7.0)
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

### 6c. `envguard watch` (new in v0.7.0)
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

### 7. `envguard baseline create`
Captures all existing repository findings into `.envguard-baseline.json`.
```bash
envguard baseline create
envguard baseline create --overwrite
```
Computes in-memory SHA-256 fingerprints. Subsequent scans suppress baseline findings, allowing adoption on legacy codebases without blocking current work.

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
│                        ENVGUARD                          │
│             Developer Security Safety Gate               │
│    Secrets • Git Protection • Environment Validation     │
└─────────────────────────────────────────────────────────┘

Project:         my-project
Path:            C:\Projects\my-project
EnvGuard:        v0.5.5
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

# Advanced Multi-Signal Detection (v0.4.0)
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

# CI/CD Configuration (v0.5.0)
ci:
  changed_files_only: true     # Only scan files changed relative to base ref
  base_branch: null            # Auto-detect default branch (main/master) or specify ref
  annotations: true            # Emit GitHub Actions ::error:: and ::warning:: annotations
  job_summary: true            # Append Markdown summary to $GITHUB_STEP_SUMMARY
```

> **Advanced Detection Engine (v0.4.0):** Combines pattern regexes, Shannon entropy calculations, structural JWT header decoding, and surrounding variable context into a centralized multi-signal scoring system. Known regex rules preserve their configured severity by design. UUIDs, Git hashes, SHA-256 digests, version numbers, and placeholders are excluded to minimize false positives. Configuration supports strict boundary validation on all fields.

---

## Organization Policy (`.envguard-org.yml`)

EnvGuard v0.6.0 introduces support for `.envguard-org.yml` (or `.envguard-org.yaml`) committed alongside `.envguard.yml`.

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
| `generic-high-entropy-secret` | High Entropy Secret | MEDIUM | Shannon entropy analysis ($H \ge 4.0$) in credential context |
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

## Developer Workflow Integration (v0.7.0)

EnvGuard v0.7.0 integrates secret detection directly into active developer workflows — eliminating friction, catching leaks earlier, and avoiding post-push secret exposure incidents.

### 1. Production Git Pre-Push Hook

While pre-commit catches uncommitted staged secrets, the **pre-push hook** serves as the definitive perimeter defense before commits leave the developer's machine and propagate to remotes.

- **Full Git Protocol Compliance**: Intercepts Git's stdin stream (`<local-ref> <local-sha> <remote-ref> <remote-sha>`) across single or multiple ref pushes.
- **Deep Commit Range Resolution**: Accurately computes commit ranges for branch updates (`remote_sha..local_sha`), new branches/tags (`--not --remotes`), and gracefully skips deletions.
- **True Git Object Inspection**: Scans files directly from Git's object store using `git diff-tree` and `git show <commit>:<path>`, catching intermediate leaks in commit chains even if undone in subsequent commits.
- **Strict Injection Defenses**: Rejects any ref or SHA starting with `-` or containing null bytes, and terminates commands with `--`.
- **Idempotent Installation**:
  ```bash
  envguard install-hook --type pre-push
  ```

### 2. Zero-Dependency Filesystem Watcher

Continuous monitoring detects secrets the moment files are saved to disk — without leaving the terminal:

- **100% Python Standard Library**: Runs using native `os.scandir` and filesystem `mtime_ns` / `size` caching with **zero third-party dependencies**.
- **Debounced Event Processing**: Configurable debounce interval (default `0.3s`) prevents scan storms and duplicate alerts during rapid saves.
- **Intelligent Pruning**: Automatically prunes `.git`, `node_modules`, `venv`, `build`, `dist`, `__pycache__`, and respects `.gitignore` and `.envguardignore`.
- **Single Detection Engine**: Reuses the core streaming engine for identical detection accuracy across all commands.
  ```bash
  # Watch current directory
  envguard watch

  # Watch specific path with custom debounce delay
  envguard watch ./src --debounce 0.5
  ```

### 3. Editor & IDE Diagnostic JSON (`--format ide`)

EnvGuard v0.7.0 provides a versioned diagnostic schema (`schema_version: 1`) engineered for IDE extensions, Language Server Protocol (LSP) daemons, and editor diagnostics (VS Code, JetBrains, Neovim):

- **1-Based Character Coordinates**: Every finding includes deterministic `line`, `column`, `end_line`, and `end_column` properties, with safe fallback coordinates (`min: 1`).
- **Guaranteed Privacy**: Plaintext secrets are strictly masked (`masked_value`) and never exposed in the JSON output.
- **Standardized Schema**:
  ```bash
  envguard scan --format ide
  envguard ci --format ide
  ```

```json
{
  "schema_version": 1,
  "tool": "envguard",
  "version": "0.7.0",
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

```text
tests/test_advanced_config.py::test_valid_advanced_detection_config PASSED
tests/test_baseline.py::test_baseline_creation_and_no_plaintext_secrets PASSED
tests/test_ci.py::test_ci_detection_github_actions PASSED
tests/test_ci.py::test_ci_detection_gitlab_ci PASSED
tests/test_ci.py::test_ci_detection_azure_pipelines PASSED
tests/test_ci.py::test_ci_detection_local PASSED
tests/test_ci_output.py::test_ci_command_clean_exit_code PASSED
tests/test_ci_output.py::test_ci_command_detects_secrets_and_blocks PASSED
tests/test_git_utils.py::test_is_git_repository PASSED
tests/test_git_utils.py::test_get_changed_files_between_commits PASSED
tests/test_github_actions.py::test_write_github_annotations PASSED
tests/test_github_actions.py::test_write_github_job_summary PASSED
tests/test_sarif.py::test_sarif_generation_schema_compliance PASSED
tests/test_sarif.py::test_sarif_severity_mappings PASSED
tests/test_scanner.py::test_scan_files_explicit_list PASSED
tests/test_v060_features.py::test_multi_repo_scanning_clean PASSED
tests/test_v066_fixes.py::test_bug_a_locked_disabled_rules_not_unknown_key PASSED
tests/test_v070_pre_push.py::test_cli_pre_push_blocking_secret PASSED
tests/test_v070_ide_json.py::test_cli_scan_ide_format PASSED
tests/test_v070_watch.py::test_watcher_detects_modification_with_debounce PASSED

============================= 190 passed in 22.23s =============================
```

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
| v0.5.3 | Bug Fix Release (Baseline Consistency, Independent Entropy Rule, Output Confirmation) | Complete |
| v0.5.4 | Security & Consistency Patch (Ref Injection Prevention, block_on Validation, Status advanced_detection, Specificity Fix, Unknown Keys Warning) | Complete |
| v0.5.5 | Micro Patch Update (Rich Console Stderr Fix, Status Command Config Warnings Surface) | Complete |
| v0.6.0 | Team & Multi-Repo Workflows (Organization Security Floor, Multi-Repo Scanning, Blocker Attribution) | Complete |
| v0.6.6 | Patch Update (Organization Policy locked_disabled_rules Schema Fix, Multi-Repo Scan TypeError Fix) | Complete |
| **v0.7.0** | **Developer Workflow Integration (Git Pre-Push Hook, Filesystem Watch Mode, IDE Diagnostic JSON)** | **Current Release ✅** |
| v1.0.0 | Stable production release | Target |


---

## License

Distributed under the MIT License. See [`LICENSE`](./LICENSE) for details.
