# Contributing to EnvGuard

Thank you for your interest in contributing to **EnvGuard**! We welcome community contributions to help improve detection accuracy, expand developer tooling integrations, and uphold our 100% local-first privacy guarantee.

---

## Code of Conduct

Please be respectful, collaborative, and considerate of all contributors.

---

## Core Guarantees & Architectural Principles

When writing or modifying code for EnvGuard, the following commitments must be maintained:

1. **100% Local-First & Privacy Preserving**:
   - EnvGuard never transmits code, secrets, configuration, or environment variables to remote servers or cloud services.
   - Zero telemetry, zero cloud dependencies, zero external network calls during scanning.

2. **Scanner Precision over False Positives**:
   - High entropy alone is never sufficient to classify a token as a secret.
   - Genuine credentials must have semantic credential context or elevated symbol diversity in variable assignments.
   - Punctuation, unquoted language syntax, booleans, and structural metadata (MIME types, CSS properties, package names) must never trigger false positives.

3. **Remediation Safety**:
   - `envguard fix --apply` must never modify clean source code without moving the secret into a `.env` file that is guaranteed to be ignored by Git.
   - Generated replacement code (e.g. `os.environ.get(...)`) must never trigger false positive findings.

4. **Deterministic Exit Codes**:
   - `0`: Clean / Success / No blocking findings
   - `1`: Blocking findings detected / Policy violation / Drift detected
   - `2`: CLI usage, configuration, or git cleanliness error
   - `3`: Fatal system / unhandled error

---

## Development Setup

EnvGuard requires **Python 3.10+**.

1. **Clone the repository**:
   ```bash
   git clone https://github.com/neil-data/envGUARD.git
   cd envGUARD
   ```

2. **Create a virtual environment**:
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On Linux/macOS:
   source venv/bin/activate
   ```

3. **Install in editable mode with development dependencies**:
   ```bash
   pip install -e .
   pip install pytest pytest-asyncio
   ```

---

## Running Tests

Run the complete test suite:
```bash
pytest -q
```

All contributions must ensure the full test suite passes with **zero unexpected failures**.

---

## Pull Request Guidelines

- Ensure your branch is based off `main`.
- Add unit tests for any new features, detector rules, or bug fixes.
- If adding a new detection pattern, test it against both positive true-secret cases and negative non-secret false-positive cases.
- Update documentation and changelog if modifying CLI commands or configuration options.
