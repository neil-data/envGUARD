<div align="center">

# 🛡️ EnvGuard

**A lightweight, developer-side safety gate for secrets and environment drift.**

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/badge/version-0.2.0-indigo.svg)](https://github.com/)
[![Local Only](https://img.shields.io/badge/privacy-100%25%20local-success.svg)](#-privacy--local-guarantees)
[![Tests](https://img.shields.io/badge/tests-36%20passed-brightgreen.svg)](#-testing)

<p align="center">
  <a href="#-key-features">Key Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-cli-commands">CLI Commands</a> •
  <a href="#-interactive-console">Interactive Console</a> •
  <a href="#-configuration-envguardyml">Configuration</a> •
  <a href="#-baseline-architecture">Baseline</a> •
  <a href="#-cicd-integration">CI/CD</a> •
  <a href="#-roadmap">Roadmap</a>
</p>

</div>

---

## 🔒 Privacy & Local Guarantees

> **EnvGuard scans repository contents locally and does not upload source code or detected secrets.**

* ✓ **No cloud backend required**
* ✓ **No API keys required**
* ✓ **No repository contents uploaded**
* ✓ **No detected secrets transmitted**
* ✓ **No telemetry by default**

All secret detection, line-by-line streaming, and SHA-256 baseline fingerprinting execute entirely in local memory on your workstation.

---

## 🗺️ Roadmap

| Version | Milestone | Status |
|---|---|:---:|
| **v0.1.0** | MVP | Complete |
| **v0.2.0** | Open-source foundation | **Current Release ✅** |
| **v0.3.0** | Developer experience & auto-remediation | Planned |
| **v0.4.0** | Advanced detection (entropy, JWT, cloud providers) | Planned |
| **v0.5.0** | CI/CD & GitHub ecosystem action | Planned |
| **v0.6.0** | Team/project workflows & multi-repo policies | Planned |
| **v1.0.0** | Stable production release | **Target 🚀** |

---

## 🌟 Key Features

* **🛑 Pre-Commit Gate (`envguard check`)**: Inspects only staged Git index content (`git show :path`). Blocks risky commits before credentials ever touch Git history.
* **🔍 Directory Scanner (`envguard scan`)**: Line-by-line streaming scanner that respects `.gitignore` and `.envguard.yml` exclusions, safely skipping binary and oversized files.
* **🔄 Environment Drift Gate (`envguard diff`)**: Compares `.env` against `.env.example` by keys only—identifying missing or stale environment variables without ever reading secret values.
* **📊 Security Dashboard (`envguard status`)**: Severity-aware health check verifying `.env` Git tracking risk, credential leaks, and hook status.
* **🗃️ Cryptographic Baseline (`envguard baseline create`)**: Suppresses existing legacy findings via SHA-256 fingerprints (`sha256:hash`). Never writes plaintext secrets to disk.
* **🎛️ Interactive Console (`envguard menu` & `envguard ui`)**: Built-in Rich dashboard and dedicated Windows Terminal (`wt.exe` / `cmd.exe`) launcher with an isolated sandbox demo.
* **🙈 Strict Secret Masking Invariant**: Full secrets are never displayed in terminal logs, JSON output, or error messages (e.g., `AKIA••••••••••••MPLE`).
* **🤖 CI/CD Ready (`--format json`)**: Standardized JSON output (`schema_version: 1`) and strict exit code contract for automated pipelines.

---

## 🚀 Installation

### Option 1: From Wheel
```bash
pip install dist/envguard-0.2.0-py3-none-any.whl
```

### Option 2: Editable / Developer Mode
```bash
git clone https://github.com/your-username/envguard.git
cd envguard
pip install -e .
```

Verify your installation:
```bash
envguard --version
# envguard, version 0.2.0
```

---

## 💻 CLI Commands

### 1. `envguard check`
Scans **only staged Git content** from the index.
```bash
envguard check
# Machine-readable JSON output:
envguard check --format json
```
* **HIGH** and **MEDIUM** severity secrets block the commit (exit code `1`).
* **LOW** severity findings warn developers without blocking (exit code `0`).

---

### 2. `envguard scan`
Recursively scans the working directory for secrets.
```bash
envguard scan
# Scan a specific directory:
envguard scan --path ./src
# Output machine-readable JSON for CI/CD:
envguard scan --format json
# Verbose mode (shows skipped binary / oversized files):
envguard scan --verbose
```

---

### 3. `envguard diff`
Compares environment variable keys between `.env` and `.env.example`.
```bash
envguard diff
# Or specify custom paths:
envguard diff --env .env.local --example .env.template
```
* Identifies variables present in `.env` but missing from `.env.example`.
* Identifies deprecated variables present in `.env.example` but not in `.env`.
* **Zero secret exposure**: values are never parsed or logged.

---

### 4. `envguard status`
Displays a severity-aware project security dashboard.
```bash
envguard status
```
* Checks Git repository status.
* Verifies whether `.env` is accidentally tracked by Git (**🔴 CRITICAL RISK**).
* Summarizes active secret findings by severity.
* Reports `.env.example` synchronization.
* Checks pre-commit hook installation status.

---

### 5. `envguard install-hook`
Installs or safely appends the EnvGuard safety gate into `.git/hooks/pre-commit`.
```bash
envguard install-hook
```
* Uses clear boundary markers (`# BEGIN ENVGUARD HOOK ... # END ENVGUARD HOOK`).
* Preserves existing hooks without overwriting user scripts.
* Executable across Windows (Git Bash, CMD, PowerShell) and Unix systems.

---

### 6. `envguard baseline create`
Captures all existing repository findings into `.envguard-baseline.json`.
```bash
envguard baseline create
# Overwrite existing baseline file:
envguard baseline create --overwrite
```
* Evaluates all current findings without baseline suppression.
* Computes in-memory SHA-256 fingerprints (`sha256:hash`).
* Subsequent scans automatically suppress baseline findings, allowing adoption on legacy codebases without blocking feature work.

---

## 🖥️ Interactive Console

### Current Terminal Menu:
```bash
envguard menu
# Or simply:
envguard
```

### Dedicated Standalone Window (Windows):
```bash
envguard ui
```
Spawns an independent, beautiful console window using **Windows Terminal (`wt.exe`)** or **Command Prompt (`cmd.exe`)**.

```text
╔═══════════════════════════════════════════════════════════════════════╗
║ ███████╗███╗   ██╗██╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗  ║
║ ██╔════╝████╗  ██║██║   ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗ ║
║ █████╗  ██╔██╗ ██║██║   ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║ ║
║ ██╔══╝  ██║╚██╗██║╚██╗ ██╔╝██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║ ║
║ ███████╗██║ ╚████║ ╚████╔╝ ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝ ║
║ ╚══════╝╚═╝  ╚═══╝  ╚═══╝   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ║
║                                                                       ║
║            Developer-Side Safety Gate for Secrets & Drift             ║
╚═══════════════════════════════════════════════════════════════════════╝

Active Workspace: C:\YourProject

┌──────────────────── Select an Option ────────────────────┐
│   [1]    📊 Project Security Status                      │
│   [2]    🔍 Scan Working Directory for Secrets           │
│   [3]    🛑 Check Staged Git Changes (Pre-commit gate)   │
│   [4]    🔄 Compare .env vs .env.example Drift           │
│   [5]    🪝 Install / Update Git Pre-Commit Hook         │
│   [6]    🧪 Run Safe Secret Leak Demo                    │
│   [0]    🚪 Exit                                         │
└──────────────────────────────────────────────────────────┘

EnvGuard> 
```

---

## ⚙️ Configuration (`.envguard.yml`)

EnvGuard works with zero configuration by default. To customize rules, file size limits, or exclusions, place a `.envguard.yml` file in your repository root:

```yaml
version: 1

scan:
  max_file_size_mb: 5          # Skip files larger than 5 MB (default)

exclude:
  - tests/fixtures/**          # Custom glob exclusions
  - vendor/**
  - generated/**

rules:
  disable:
    - generic-secret           # Disable specific rule IDs

  severity_overrides:
    api-key-assignment: HIGH   # Override default severity

placeholders:
  - my_dummy_api_key           # Add custom whitelisted placeholders
  - test_mock_token

git:
  block_on:
    - HIGH                     # Severities that block commits
    - MEDIUM
```

---

## 🏷️ Stable Rule IDs

Every detection rule has a permanent, stable identifier for configuration and reporting:

| Rule ID | Rule Name | Default Severity | Target / Pattern |
|---|---|:---:|---|
| `aws-access-key` | AWS Access Key | **HIGH** | AWS Access Key ID (`AKIA...`) |
| `github-token` | GitHub Personal Access Token | **HIGH** | Classic `ghp_` or fine-grained `github_pat_` |
| `stripe-secret-key` | Stripe Secret Key | **HIGH** | Stripe API Keys (`sk_*`, `rk_*`) |
| `pem-private-key` | Private Key | **HIGH** | OpenSSL / PEM Private Key header |
| `api-key-assignment` | API Key Assignment | **MEDIUM** | Assignments with `API_KEY` |
| `secret-assignment` | Secret Assignment | **MEDIUM** | Assignments with `SECRET` |
| `secret-key-assignment`| Secret Key Assignment | **MEDIUM** | Assignments with `SECRET_KEY` |
| `password-assignment` | Password Assignment | **MEDIUM** | Assignments with `PASSWORD` |
| `db-password-assignment`| Database Password | **MEDIUM** | Assignments with `DB_PASSWORD` |
| `token-assignment` | Token Assignment | **MEDIUM** | Assignments with `TOKEN` |
| `generic-credential` | Generic Credential | **LOW** | Assignments with `credential` |
| `generic-secret` | Generic Secret | **LOW** | Assignments with `key` |

---

## 🚦 Exit Code Contract

EnvGuard maintains a strict, documented exit-code contract suitable for CI/CD automation:

| Exit Code | Meaning | Example Scenario |
|:---:|---|---|
| `0` | **Success / Clean** | No blocking findings, files synchronized, or warnings only. |
| `1` | **Blocking Findings** | Staged HIGH/MEDIUM secrets found, or unsuppressed scan findings. |
| `2` | **Runtime / Config Error**| Invalid `.envguard.yml`, missing required file, or Git error. |
| `3` | **Invalid CLI Usage** | Unknown CLI flags, missing required arguments, or bad options. |

---

## 🤖 CI/CD Integration

EnvGuard is non-interactive and ready for automated pull-request and build checks. Add this workflow to `.github/workflows/envguard.yml`:

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

## 🧪 Testing

EnvGuard is backed by a comprehensive unit test suite:

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
tests/test_json_output.py::test_scan_json_output_clean PASSED
tests/test_json_output.py::test_scan_json_output_with_findings PASSED
tests/test_json_output.py::test_diff_json_output PASSED
tests/test_json_output.py::test_status_json_output PASSED
tests/test_performance.py::test_large_file_is_skipped PASSED
tests/test_performance.py::test_exit_code_contract PASSED
...
============================= 36 passed in 0.95s ==============================
```

---

## 🛡 License

Distributed under the **MIT** License. See `LICENSE` for more information.
