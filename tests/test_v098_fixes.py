"""Tests for EnvGuard v0.9.8 fixes.

Covers:
1. Safe code expressions (os.environ.get, os.getenv, get_secret_key_from_vault) do not re-trigger scanner.
2. Hardcoded passwords remain accurately detected.
3. .envguard-baseline.json and .envguard*.json/.yml files are excluded by built-in ignore.
4. envguard doctor reports Python floor >= 3.10 compatibility.
5. Inconsistent path argument handling (positional path support for baseline create, doctor, status, init).
"""

from pathlib import Path
import sys
from click.testing import CliRunner
import pytest

from envguard.cli import main
from envguard.diagnostics import run_diagnostics
from envguard.ignore import is_path_ignored, should_ignore_file
from envguard.patterns import load_default_patterns
from envguard.scanner import scan_directory


def test_fix_generated_safe_code_not_flagged(tmp_path: Path):
    """Bug 1: fix-generated and standard environment/vault code expressions should not be flagged."""
    code_file = tmp_path / "app.py"
    code_file.write_text(
        """
import os

password = os.environ.get("PASSWORD")
db_password = os.getenv("DB_PASSWORD")
database_password = os.environ.get("DATABASE_PASSWORD")
secret_key = get_secret_key_from_vault()
api_key = os.environ.get("API_KEY")
auth_token = os.getenv("AUTH_TOKEN")
""",
        encoding="utf-8",
    )

    patterns = load_default_patterns()
    findings = scan_directory(directory=tmp_path, patterns=patterns)
    assert len(findings) == 0, f"Expected 0 findings in safe code, but got: {[f.rule_id for f in findings]}"

    # Also run CLI scan command
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "SCAN PASSED" in result.output or "No secrets were detected" in result.output


def test_hardcoded_passwords_still_flagged(tmp_path: Path):
    """Ensure genuine hardcoded password assignments remain properly detected."""
    code_file = tmp_path / "unsafe.py"
    code_file.write_text(
        """
password = "hardcoded_password_123"
db_password = "super_secret_db_pass"
""",
        encoding="utf-8",
    )

    patterns = load_default_patterns()
    findings = scan_directory(directory=tmp_path, patterns=patterns)
    assert len(findings) >= 2
    rule_ids = {f.rule_id for f in findings}
    assert "password-assignment" in rule_ids
    assert "db-password-assignment" in rule_ids


def test_baseline_and_config_files_ignored(tmp_path: Path):
    """Bug 2: .envguard-baseline.json and config files must be excluded from scanning."""
    assert should_ignore_file(".envguard-baseline.json") is True
    assert should_ignore_file(".envguard.yml") is True
    assert should_ignore_file(".envguard-org.yml") is True
    assert should_ignore_file(".envguardignore") is True

    ignored, reason = is_path_ignored(".envguard-baseline.json")
    assert ignored is True
    assert reason == "builtin"

    # Write a baseline file with high-entropy looking strings
    baseline_file = tmp_path / ".envguard-baseline.json"
    baseline_file.write_text(
        """
{
  "version": 1,
  "fingerprints": [
    "a1b2c3d4e5f678901234567890abcdef12345678",
    "f1e2d3c4b5a678901234567890fedcba12345678"
  ]
}
""",
        encoding="utf-8",
    )

    patterns = load_default_patterns()
    findings = scan_directory(directory=tmp_path, patterns=patterns)
    assert len(findings) == 0


def test_doctor_python_floor(tmp_path: Path):
    """Bug 4: doctor reports Python >= 3.10 floor compatibility."""
    report = run_diagnostics(tmp_path)
    py_checks = [c for c in report.checks if c.name == "Python Runtime"]
    assert len(py_checks) == 1
    py_check = py_checks[0]

    if sys.version_info >= (3, 10):
        assert py_check.status == "PASS"
        assert "Compatible >= 3.10" in py_check.details
    else:
        assert py_check.status == "WARNING"
        assert "3.10 or newer" in py_check.recommendation


def test_baseline_create_positional_path(tmp_path: Path):
    """Minor UX: baseline create should accept optional positional PATH argument."""
    # Create clean file
    f = tmp_path / "hello.py"
    f.write_text("print('hello world')\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["baseline", "create", str(tmp_path)])
    assert result.exit_code == 0
    assert "BASELINE CREATED" in result.output
    assert (tmp_path / ".envguard-baseline.json").exists()


def test_doctor_and_status_positional_path(tmp_path: Path):
    """Minor UX: doctor and status should accept optional positional PATH argument."""
    runner = CliRunner()
    res_doc = runner.invoke(main, ["doctor", str(tmp_path)])
    assert res_doc.exit_code == 0

    res_stat = runner.invoke(main, ["status", str(tmp_path)])
    assert res_stat.exit_code == 0
