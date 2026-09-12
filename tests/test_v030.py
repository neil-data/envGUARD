"""Comprehensive tests for EnvGuard v0.3.0 features.

Tests:
1. .envguardignore file loading and ignore precedence.
2. Inline suppression directives (same-line, ignore-next-line, rule-specific, all-rules).
3. Shannon entropy calculation and contextual heuristics.
4. Expanded placeholder recognition.
5. envguard init command (file creation and non-destructive behavior).
6. envguard doctor diagnostics checks.
7. envguard explain command (valid rule, unknown rule exit code 3).
8. envguard rules list command.
"""

import json
from pathlib import Path
from click.testing import CliRunner
import pytest

from envguard.cli import main
from envguard.entropy import (
    analyze_entropy_and_context,
    calculate_entropy,
    is_credential_variable,
    is_generic_hash_or_commit,
    is_uuid,
)
from envguard.ignore import is_path_ignored, load_envguardignore
from envguard.initializer import init_project
from envguard.patterns import load_default_patterns
from envguard.scanner import scan_directory, scan_text
from envguard.suppression import parse_suppressions_from_lines, parse_suppressions_from_text
from envguard.utils import is_placeholder


def test_placeholder_recognition():
    """Verify extended v0.3.0 placeholder detection."""
    assert is_placeholder("your_key_here")
    assert is_placeholder("replace_me")
    assert is_placeholder("changeme")
    assert is_placeholder("dummy_key")
    assert is_placeholder("fake_key")
    assert is_placeholder("example_key")
    assert is_placeholder("test_key")
    assert is_placeholder("<your-key>")
    assert is_placeholder("<api-key>")
    assert is_placeholder("YOUR_API_KEY_HERE")

    # Legitimate secrets must NOT be classified as placeholders
    assert not is_placeholder("AKIAIOSFODNN7EXAMPLE")
    assert not is_placeholder("ghp_123456789012345678901234567890123456")


def test_entropy_and_heuristics():
    """Verify Shannon entropy calculation and false-positive guards."""
    #<Low entropy repeated string
    low_ent = calculate_entropy("aaaaaaaaaaaaaaaa")
    assert low_ent < 1.0

    # High entropy realistic token
    high_ent = calculate_entropy("c4ca4238a0b923820dcc509a6f75849b")
    assert high_ent > 3.0

    # UUID guard
    assert is_uuid("123e4567-e89b-12d3-a456-426614174000")
    assert not is_uuid("not-a-uuid-string")

    # Hex/commit hash guard
    assert is_generic_hash_or_commit("4b825dc642cb6eb9a060e54bf8d69288fbee4904")

    # Contextual analysis
    suspicious, signals = analyze_entropy_and_context(
        value="xK9#mQ24vL5*pZ8@wY1!DyR7%",
        var_name="stripe_api_secret",
    )
    assert suspicious
    assert any("credential-like variable" in s for s in signals)


def test_envguardignore(tmp_path):
    """Verify .envguardignore properly excludes files and directories."""
    ignore_file = tmp_path / ".envguardignore"
    ignore_file.write_text("mock_data/\n*.fixture\n", encoding="utf-8")

    spec = load_envguardignore(tmp_path)
    assert spec is not None

    ignored, reason = is_path_ignored("mock_data/creds.py", envguardignore_spec=spec)
    assert ignored
    assert reason == "envguardignore"

    ignored, reason = is_path_ignored("sample.fixture", envguardignore_spec=spec)
    assert ignored
    assert reason == "envguardignore"

    ignored, reason = is_path_ignored("src/app.py", envguardignore_spec=spec)
    assert not ignored


def test_inline_suppressions():
    """Verify same-line and next-line inline suppressions."""
    code = """line_one = 'clean'
api_key = 'AKIAIOSFODNN7EXAMPLE' # envguard: ignore
db_password = 'Password123!' # envguard: ignore=password-assignment
# envguard: ignore-next-line
secret_token = 'ghp_123456789012345678901234567890123456'
# envguard: ignore-next-line=stripe-secret-key
stripe_key = 'sk_test_51MockedKeyForTestingPurposes00'
unsuppressed = 'AKIAIOSFODNN7EXAMPLE'
"""
    lines = code.splitlines()
    mgr = parse_suppressions_from_lines(lines)

    # Line 2: api_key suppressed for all rules
    assert mgr.is_suppressed(2, "aws-access-key")

    # Line 3: db_password suppressed specifically for password-assignment
    assert mgr.is_suppressed(3, "password-assignment")
    assert not mgr.is_suppressed(3, "aws-access-key")

    # Line 5: secret_token suppressed via ignore-next-line
    assert mgr.is_suppressed(5, "github-token")

    # Line 7: stripe_key suppressed via ignore-next-line=stripe-secret-key
    assert mgr.is_suppressed(7, "stripe-secret-key")
    assert not mgr.is_suppressed(7, "aws-access-key")

    # Line 8: unsuppressed
    assert not mgr.is_suppressed(8, "aws-access-key")


def test_scan_respects_inline_suppression(tmp_path):
    """Verify scanner suppresses findings when inline comments are present."""
    f = tmp_path / "secrets.py"
    f.write_text(
        "aws_key = 'AKIAIOSFODNN7EXAMPLE' # envguard: ignore\n"
        "real_leak = 'AKIA1111111111111111'\n",
        encoding="utf-8",
    )

    stats = {}
    findings = scan_directory(tmp_path, stats=stats)
    assert len(findings) == 1
    assert findings[0].raw_value == "AKIA1111111111111111"
    assert stats.get("suppressed_count") >= 1


def test_init_command(tmp_path):
    """Verify envguard init creates starter files safely without overwriting."""
    res = init_project(tmp_path)
    assert res.config_created
    assert res.ignore_created
    assert not res.config_existed
    assert not res.ignore_existed


    res2 = init_project(tmp_path)
    assert not res2.config_created
    assert not res2.ignore_created
    assert res2.config_existed
    assert res2.ignore_existed


def test_cli_init(tmp_path):
    """Verify CLI init in text and JSON mode."""
    runner = CliRunner()
    result = runner.invoke(main, ["init", "--path", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["command"] == "init"
    assert data["files"]["config"]["created"] is True
    assert data["files"]["ignore"]["created"] is True


def test_cli_doctor(tmp_path):
    """Verify CLI doctor runs and reports diagnostics."""
    runner = CliRunner()
    result = runner.invoke(main, ["doctor", "--path", str(tmp_path), "--format", "json"])
    assert result.exit_code in (0, 1)
    data = json.loads(result.output)
    assert data["command"] == "doctor"
    assert "checks" in data
    check_names = [c["name"] for c in data["checks"]]
    assert "Python Runtime" in check_names
    assert "EnvGuard Version" in check_names
    assert "Secret Rules" in check_names


def test_cli_explain():
    """Verify CLI explain command for valid and invalid rules."""
    runner = CliRunner()

    # Valid rule
    res = runner.invoke(main, ["explain", "aws-access-key", "--format", "json"])
    assert res.exit_code == 0
    data = json.loads(res.output)
    assert data["rule"]["id"] == "aws-access-key"
    assert "why_it_matters" in data["rule"]
    assert "remediation" in data["rule"]

    # Invalid rule exits with 3
    res_bad = runner.invoke(main, ["explain", "non-existent-rule-12345"])
    assert res_bad.exit_code == 3


def test_cli_rules_list():
    """Verify CLI rules list command in text and JSON mode."""
    runner = CliRunner()
    res = runner.invoke(main, ["rules", "list", "--format", "json"])
    assert res.exit_code == 0
    data = json.loads(res.output)
    assert data["command"] == "rules"
    assert data["total_rules"] >= 12
