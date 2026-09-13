"""Regression tests for EnvGuard v0.5.3 bug fixes:
Bug #1: Baseline validity consistency between status and doctor.
Bug #2: generic-high-entropy-secret triggers independently with false-positive protections.
Bug #3: Output written confirmation message on --output.
"""

import json
from pathlib import Path
from click.testing import CliRunner
import pytest

from envguard import __version__
from envguard.baseline import create_baseline, inspect_baseline
from envguard.cli import main
from envguard.detectors.entropy_detector import (
    calculate_entropy,
    detect_entropy_candidates,
    is_code_expression,
    is_env_or_code_context,
    is_regex_literal,
)
from envguard.detectors.scoring import AdvancedDetectionConfig
from envguard.diagnostics import run_diagnostics
from envguard.patterns import load_default_patterns
from envguard.scanner import scan_lines, scan_text


def test_v053_version():
    """Verify version bumped to 0.5.3."""
    assert __version__ == "0.5.3"
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.5.3" in result.output


def test_bug_1_status_and_doctor_agree_on_baseline(tmp_path, monkeypatch):
    """Bug #1: envguard status and envguard doctor agree on baseline validity and fingerprint count."""
    (tmp_path / ".git").mkdir()
    monkeypatch.setattr(Path, "cwd", lambda: tmp_path)

    patterns = load_default_patterns()
    dummy_findings = scan_text("API_KEY = 'AKIAIOSFODNN7EXAMPLE'\n", "test.py", patterns)
    baseline_file = tmp_path / ".envguard-baseline.json"
    create_baseline(dummy_findings, baseline_file)

    # 1. Verify shared inspect_baseline returns valid state and count
    exists, count, error = inspect_baseline(baseline_file)
    assert exists is True
    assert count >= 1
    assert error is None

    # 2. Verify doctor reports PASS with fingerprint count
    diag = run_diagnostics(tmp_path)
    baseline_check = next((c for c in diag.checks if c.name == "Historical Baseline"), None)
    assert baseline_check is not None
    assert baseline_check.status == "PASS"
    assert f"present ({count} fingerprints)" in baseline_check.details

    # 3. Verify status command does NOT report INVALID
    runner = CliRunner()
    result = runner.invoke(main, ["status"])
    assert result.exit_code == 0
    assert "INVALID" not in result.output
    assert f"ACTIVE ({count} entries)" in result.output

    # 4. Corrupt baseline and verify BOTH report failure
    baseline_file.write_text("{corrupt-json", encoding="utf-8")
    exists, count, error = inspect_baseline(baseline_file)
    assert exists is True
    assert count == 0
    assert error is not None

    diag_corrupt = run_diagnostics(tmp_path)
    b_check_corrupt = next((c for c in diag_corrupt.checks if c.name == "Historical Baseline"), None)
    assert b_check_corrupt.status == "ERROR"

    result_corrupt = runner.invoke(main, ["status"])
    assert "INVALID" in result_corrupt.output


def test_bug_2_generic_high_entropy_secret_triggers_independently():
    """Bug #2: generic-high-entropy-secret triggers independently when no specific regex matches."""
    cfg = AdvancedDetectionConfig(entropy_enabled=True, entropy_threshold=4.0, entropy_min_length=20)
    patterns = load_default_patterns()

    # 1. Arbitrary variable with high-entropy value (no AWS/Google/GitHub prefix, no credential keyword in var name)
    line = "CONFIG_PARAM_X = '9xK#mQ2!pZ1@4vL8wB7$dE3*yT6&'"
    findings = scan_lines([line], "settings.py", patterns, advanced_config=cfg)
    assert len(findings) == 1
    assert findings[0].rule_id == "generic-high-entropy-secret"
    assert findings[0].severity == "MEDIUM"

    # 2. Standalone quoted literal with high entropy in a call or config
    call_line = "verify_custom_token('7qJ!9pL#2vK*8xN$4wM@1zP&5yT^')"
    findings_call = scan_lines([call_line], "auth.py", patterns, advanced_config=cfg)
    assert len(findings_call) == 1
    assert findings_call[0].rule_id == "generic-high-entropy-secret"
    assert findings_call[0].severity == "MEDIUM"

    # 3. Specific provider rules must still take priority over entropy
    aws_line = "CUSTOM_AWS = 'AKIAIOSFODNN7EXAMPLE'"
    findings_aws = scan_lines([aws_line], "aws.py", patterns, advanced_config=cfg)
    assert len(findings_aws) == 1
    assert findings_aws[0].rule_id == "aws-access-key"
    assert findings_aws[0].severity == "HIGH"


def test_bug_2_false_positive_protections():
    """Bug #2: Verify false-positive protections for env lookups, re.compile, regex literals, function calls, UUIDs, hashes."""
    cfg = AdvancedDetectionConfig(entropy_enabled=True, entropy_threshold=3.5, entropy_min_length=15)
    patterns = load_default_patterns()

    safe_lines = [
        # os.environ.get and os.getenv
        "PROD_KEY = os.environ.get('PROD_API_KEY_ENVIRONMENT_VAR_NAME')",
        "ACCESS_KEY = os.getenv('MY_CUSTOM_ACCESS_KEY_IDENTIFIER')",
        # re.compile and regex literals
        "PATTERN = re.compile(r'^[a-zA-Z0-9_-]{24,32}$') ",
        "REGEX_VAL = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'",
        # Function/method call results
        "SECRET_VAL = generate_random_token_from_system()",
        "SESSION_KEY = request.headers.get('X-Session-Token')",
        # UUIDs
        "ID_VAL = '123e4567-e89b-12d3-a456-426614174000'",
        # Git commit hash / checksum in non-credential context
        "COMMIT_ID = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'",
        "BUILD_DIGEST = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'",
    ]

    for line in safe_lines:
        cands = detect_entropy_candidates(line, 1, "test.py", cfg)
        assert len(cands) == 0, f"False positive candidate detected on: {line}"
        findings = scan_lines([line], "test.py", patterns, advanced_config=cfg)
        severe = [f for f in findings if f.rule_id == "generic-high-entropy-secret"]
        assert len(severe) == 0, f"False positive finding detected on: {line}"


def test_bug_3_output_confirmation_message(tmp_path):
    """Bug #3: envguard displays a clear terminal confirmation when --output is specified."""
    test_file = tmp_path / "secret.py"
    test_file.write_text("MY_TOKEN = '9xK#mQ2!pZ1@4vL8wB7$dE3*yT6&'\n", encoding="utf-8")
    out_file = tmp_path / "report.json"

    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--format", "json", "--output", str(out_file)])

    # Output confirmation must be displayed in terminal output
    assert "Output written to:" in result.output
    assert str(out_file) in result.output or out_file.name in result.output

    # File must exist and contain valid uncorrupted JSON
    assert out_file.is_file()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["command"] == "scan"
    assert data["status"] == "failed"
    assert len(data["findings"]) >= 1

    # Text format output
    out_txt = tmp_path / "report.txt"
    result_txt = runner.invoke(main, ["scan", str(tmp_path), "--output", str(out_txt)])
    assert "Output written to:" in result_txt.output
    assert out_txt.is_file()
