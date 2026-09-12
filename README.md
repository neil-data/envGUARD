<div align="center">

# EnvGuard

**A lightweight, developer-side safety gate for secrets and environment drift.**

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/badge/version-0.2.5-indigo.svg)](https://github.com/neil-data/envGUARD/releases)
[![Local Only](https://img.shields.io/badge/privacy-100%25%20local-success.svg)](#privacy-and-local-guarantees)
[![Tests](https://img.shields.io/badge/tests-47%20passed-brightgreen.svg)](#testing)

<p>
  <a href="#why-envguard">Why EnvGuard</a> ·
  <a href="#key-features">Key Features</a> ·
  <a href="#installation">Installation</a> ·
  <a href="#cli-commands">CLI Commands</a> ·
  <a href="#interactive-console">Interactive Console</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#cicd-integration">CI/CD</a> ·
  <a href="#roadmap">Roadmap</a>
</p>

</div>

---

## Why EnvGuard

Secret leaks into Git are one of the most common, preventable security incidents in software development — a misconfigured `.gitignore`, a key pasted into a tracked file, or a commit made before anyone double-checks what's staged. Existing scanners such as Gitleaks and TruffleHog are excellent, but they're built for CI pipelines and security teams, not the moment right before a developer runs `git commit`.

EnvGuard fills that gap: a single lightweight CLI, installed in seconds, that catches secrets before they ever leave your machine — and, uniquely, keeps `.env` and `.env.example` in sync so a team never loses time to a missing environment variable.

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

All secret detection, line-by-line streaming, and SHA-256 baseline fingerprinting run entirely in local memory on your machine.

---

## Key Features

| Feature | Description |
|---|---|
| **Pre-Commit Gate** (`envguard check`) | Inspects only staged Git index content (`git show :path`), blocking risky commits before credentials touch Git history. |
| **Directory Scanner** (`envguard scan`) | Line-by-line streaming scan that respects `.gitignore` and `.envguard.yml` exclusions, safely skipping binary and oversized files. |
| **Environment Drift Gate** (`envguard diff`) | Compares `.env` against `.env.example` by key only, flagging missing or stale variables without ever reading secret values. |
| **Security Dashboard** (`envguard status`) | Severity-aware health check covering `.env` Git-tracking risk, credential leaks, baseline status, and hook status. |
| **Cryptographic Baseline** (`envguard baseline create`) | Suppresses existing legacy findings via SHA-256 fingerprints. Adopt EnvGuard on an old codebase without blocking current work. Never writes plaintext secrets to disk. |
| **Interactive Console** (`envguard menu` / `envguard ui`) | A built-in Rich dashboard, plus a dedicated Windows Terminal / Command Prompt launcher with a sandboxed demo mode. |
| **Strict Secret Masking** | Full secrets are never printed in terminal output, JSON, or error messages (e.g. `AKIA••••••••••••MPLE`). |
| **CI/CD Ready** | Standardized JSON output (`schema_version: 1`) and a strict exit-code contract for automated pipelines. |

---

## Installation

**Option 1 — From wheel**
```bash
pip install dist/envguard-0.2.5-py3-none-any.whl
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
# EnvGuard version 0.2.5
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

#### Blocked Commit Screen:
```text
┌──────────────────────────────────────────────────────────┐
│                                                          │
│                 ENVGUARD BLOCKED COMMIT                  │
│                                                          │
│ Blocking security findings were detected in staged units │
│                                                          │
│            HIGH: 1          MEDIUM: 1                    │
│                                                          │
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
Recursively scans the working directory for secrets with real-time feedback.
```bash
envguard scan
envguard scan --path ./src
envguard scan --format json
envguard scan --verbose
```

#### Scan Complete Output:
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

### 3. `envguard diff`
Compares environment variable keys between `.env` and `.env.example`.
```bash
envguard diff
envguard diff --env .env.local --example .env.template
```
Flags variables present in `.env` but missing from `.env.example`, and vice versa. Values are never parsed or logged.

#### Drift Report:
```text
┌──────────── ENVIRONMENT CONFIGURATION DRIFT ────────────┐
│ .env variables: 12      .env.example variables: 10      │
└─────────────────────────────────────────────────────────┘

┌──────────────────────────┬──────────────────────┐
│ Status                   │ Environment Variable │
├──────────────────────────┼──────────────────────┤
│ Missing from .env.example│ ✗ STRIPE_WEBHOOK_KEY │
│ Missing from .env.example│ ✗ SENTRY_DSN         │
├──────────────────────────┼──────────────────────┤
│ Extra in .env.example    │ ⚠ DEPRECATED_URL    │
└──────────────────────────┴──────────────────────┘
```

---

### 4. `envguard status`
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
│                                                        │
│  All security checks passed. Repository is protected.  │
└────────────────────────────────────────────────────────┘
```

---

### 5. `envguard install-hook`
Installs or safely appends the EnvGuard safety gate into `.git/hooks/pre-commit`.
```bash
envguard install-hook
```
* Clear boundary markers (`# BEGIN ENVGUARD HOOK ... # END ENVGUARD HOOK`)
* Preserves existing hooks without overwriting user scripts
* Runs automatically before every commit

---

### 6. `envguard baseline create`
Captures all existing repository findings into `.envguard-baseline.json`.
```bash
envguard baseline create
envguard baseline create --overwrite
```
Computes in-memory SHA-256 fingerprints. Subsequent scans suppress baseline findings, allowing adoption on legacy codebases without blocking current work.

---

## Interactive Console

Run `envguard menu` (or simply `envguard`) for the interactive console, or `envguard ui` to open it in a dedicated window:

```text
┌─────────────────────────────────────────────────────────┐
│                                                         │
│                        ENVGUARD                         │
│             Developer Security Safety Gate              │
│                                                         │
│    Secrets • Git Protection • Environment Validation    │
│                                                         │
└─────────────────────────────────────────────────────────┘

Project:         my-project
Path:            C:\Projects\my-project
EnvGuard:        v0.2.5
Git Repository:  Detected

┌─────────── Select an Option ────────────┐
│   [1]    Project Security Status        │
│   [2]    Scan Working Directory         │
│   [3]    Check Staged Git Changes       │
│   [4]    Compare .env vs .env.example   │
│   [5]    Install Pre-Commit Hook        │
│   [6]    Create / Update Baseline       │
│   [7]    Run Safe Secret Leak Demo      │
│   [0]    Exit                           │
└─────────────────────────────────────────┘

Select an option: 
```

---

## Configuration

EnvGuard works with zero configuration. To customize rules, size limits, or exclusions, add a `.envguard.yml` to your repository root:

```yaml
version: 1

scan:
  max_file_size_mb: 5          # Skip files larger than 5 MB (default)

exclude:
  - tests/fixtures/**          # Glob exclusions
  - vendor/**
  - generated/**

rules:
  disable:
    - generic-secret           # Disable specific rule IDs

  severity_overrides:
    api-key-assignment: HIGH   # Override default severity

placeholders:
  - my_dummy_api_key           # Whitelisted placeholders
  - test_mock_token

git:
  block_on:
    - HIGH                     # Severities that block commits
    - MEDIUM
```

---

## Stable Rule IDs

| Rule ID | Rule Name | Default Severity | Target / Pattern |
|---|---|:---:|---|
| `aws-access-key` | AWS Access Key | HIGH | AWS Access Key ID (`AKIA...`) |
| `github-token` | GitHub Personal Access Token | HIGH | Classic `ghp_` or fine-grained `github_pat_` |
| `stripe-secret-key` | Stripe Secret Key | HIGH | Stripe API keys (`sk_*`, `rk_*`) |
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

## CI/CD Integration

EnvGuard is non-interactive and ready for automated PR and build checks. Add to `.github/workflows/envguard.yml`:

```yaml
name: EnvGuard Security Gate

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install EnvGuard
        run: pip install .

      - name: Run EnvGuard Security Scan
        run: envguard scan --format json
```

---

## Testing

```bash
pytest -v
```

```text
tests/test_baseline.py::test_baseline_creation_and_no_plaintext_secrets PASSED
tests/test_baseline.py::test_baseline_overwrite_safety PASSED
tests/test_baseline.py::test_baseline_filters_known_and_identifies_new PASSED
tests/test_config.py::test_missing_config_returns_defaults PASSED
tests/test_config.py::test_valid_config_overrides_defaults PASSED
tests/test_config.py::test_invalid_yaml_raises_configuration_error PASSED
tests/test_config.py::test_unsupported_version_raises_configuration_error PASSED
tests/test_config.py::test_invalid_severity_override_raises_configuration_error PASSED
tests/test_config.py::test_unknown_rule_id_generates_warning PASSED
tests/test_env_diff.py::test_env_diff_specification_case PASSED
tests/test_env_diff.py::test_env_parser_supports_export_and_comments PASSED
tests/test_env_diff.py::test_env_diff_synchronized PASSED
tests/test_interactive.py::test_menu_exit_on_zero PASSED
tests/test_interactive.py::test_menu_handles_invalid_input_then_exits PASSED
tests/test_interactive.py::test_menu_actions_invoke_reusable_core_functions PASSED
tests/test_interactive.py::test_safe_demo_uses_temp_directory_and_cleans_up PASSED
tests/test_interactive.py::test_launch_separate_terminal_on_windows PASSED
tests/test_interactive.py::test_launch_separate_terminal_fallback_cmd PASSED
tests/test_interactive.py::test_launch_separate_terminal_non_windows_fallback PASSED
tests/test_json_output.py::test_scan_json_output_clean PASSED
tests/test_json_output.py::test_scan_json_output_with_findings PASSED
tests/test_json_output.py::test_diff_json_output PASSED
tests/test_json_output.py::test_status_json_output PASSED
tests/test_patterns.py::test_load_default_patterns PASSED
tests/test_patterns.py::test_mask_secret_never_reveals_full_secret PASSED
tests/test_patterns.py::test_mask_secret_private_key PASSED
tests/test_patterns.py::test_mask_secret_empty_or_edge_cases PASSED
tests/test_performance.py::test_large_file_is_skipped PASSED
tests/test_performance.py::test_exit_code_contract PASSED
tests/test_scanner.py::test_detect_aws_access_key PASSED
tests/test_scanner.py::test_detect_github_token PASSED
tests/test_scanner.py::test_detect_stripe_key PASSED
tests/test_scanner.py::test_detect_pem_private_key PASSED
tests/test_scanner.py::test_ignore_placeholder_values PASSED
tests/test_scanner.py::test_ignore_empty_api_key PASSED
tests/test_scanner.py::test_scan_directory_skips_binary_files PASSED
tests/test_ui.py::test_theme_format_severity PASSED
tests/test_ui.py::test_theme_panels_creation PASSED
tests/test_ui.py::test_scan_findings_renders_table_with_masked_secrets PASSED
tests/test_ui.py::test_scan_findings_clean_success PASSED
tests/test_ui.py::test_blocked_commit_screen_renders_remediation PASSED
tests/test_check_passed_screens PASSED
tests/test_ui.py::test_diff_report_rendering PASSED
tests/test_ui.py::test_status_dashboard_rendering PASSED
tests/test_ui.py::test_hook_installed_feedback PASSED
tests/test_ui.py::test_interactive_menu_options_display PASSED
tests/test_ui.py::test_interactive_menu_baseline_option PASSED

============================= 47 passed in 1.51s ==============================
```

---

## Roadmap

| Version | Milestone | Status |
|---|---|:---:|
| v0.1.0 | MVP | Complete |
| v0.2.0 | Open-source foundation | Complete |
| **v0.2.5** | **Rich terminal UI & Developer experience upgrade** | **Current Release ✅** |
| v0.3.0 | Developer experience & auto-remediation | Planned |
| v0.4.0 | Advanced detection (entropy, JWT, cloud providers) | Planned |
| v0.5.0 | CI/CD & GitHub ecosystem action | Planned |
| v0.6.0 | Team/project workflows & multi-repo policies | Planned |
| v1.0.0 | Stable production release | Target 🚀 |

---

## License

Distributed under the MIT License. See [`LICENSE`](./LICENSE) for details.
