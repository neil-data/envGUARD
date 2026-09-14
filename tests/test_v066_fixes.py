"""Regression tests for EnvGuard v0.6.6 bug fixes:
- Bug A: .envguard-org.yml's locked_disabled_rules field is not flagged as unknown key
- Bug B: envguard scan --repos does not crash with TypeError on text output when repos have findings
"""

import json
import os
from pathlib import Path
import pytest
from click.testing import CliRunner

from envguard import __version__
from envguard.cli import main
from envguard.config import load_config, load_raw_config_file
from envguard.diagnostics import run_diagnostics
from envguard.reporter import print_scan_findings
from envguard.scanner import ScanFinding


@pytest.fixture
def runner():
    return CliRunner()


def test_v066_version_bump(runner):
    """Verify EnvGuard version is 0.6.6."""
    assert __version__ == "0.6.6"
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.6.6" in result.output


def test_bug_a_locked_disabled_rules_not_unknown_key(tmp_path):
    """Bug A: locked_disabled_rules in .envguard-org.yml is a recognized schema field and emits no warning."""
    org_file = tmp_path / ".envguard-org.yml"
    org_file.write_text(
        "version: 1\n"
        "locked_disabled_rules:\n"
        "  - generic-secret\n"
        "scan:\n"
        "  block_on:\n"
        "    - HIGH\n",
        encoding="utf-8",
    )

    # 1. load_raw_config_file must not emit unknown key warning
    org_cfg = load_raw_config_file(org_file)
    assert not any("locked_disabled_rules" in w for w in org_cfg.warnings)
    assert "generic-secret" in org_cfg.disabled_rules
    assert "generic-secret" in org_cfg.locked_disabled_rules

    # 2. doctor diagnostics must report PASS on Organization Policy
    report = run_diagnostics(tmp_path)
    org_diag = next(c for c in report.checks if c.name == "Organization Policy")
    assert org_diag.status == "PASS"
    assert "active" in org_diag.details.lower()

    # 3. load_config composite must preserve locked_disabled_rules without warning
    config = load_config(root_dir=tmp_path)
    assert not any("locked_disabled_rules" in w for w in config.warnings)
    assert "generic-secret" in config.disabled_rules
    assert "generic-secret" in config.org_config.locked_disabled_rules


def test_bug_a_status_dashboard_shows_active(tmp_path, runner):
    """Bug A: envguard status shows ACTIVE organization policy when locked_disabled_rules is present."""
    org_file = tmp_path / ".envguard-org.yml"
    org_file.write_text(
        "version: 1\n"
        "locked_disabled_rules:\n"
        "  - generic-secret\n",
        encoding="utf-8",
    )

    orig = os.getcwd()
    os.chdir(tmp_path)
    try:
        # JSON output
        result_json = runner.invoke(main, ["status", "--format", "json"])
        assert result_json.exit_code == 0
        data = json.loads(result_json.output)
        assert data["checks"]["organization_policy"]["present"] is True
        assert data["checks"]["organization_policy"]["status"] == "ACTIVE"

        # Text output dashboard
        result_text = runner.invoke(main, ["status"])
        assert result_text.exit_code == 0
        assert "ACTIVE (.envguard-org.yml)" in result_text.output
        assert "Unknown top-level key 'locked_disabled_rules'" not in result_text.output
    finally:
        os.chdir(orig)


def test_bug_b_multi_repo_text_scan_with_findings(tmp_path, runner):
    """Bug B: envguard scan --repos does not crash with TypeError when a repo has findings in text mode."""
    repo1 = tmp_path / "repo1"
    repo1.mkdir()
    (repo1 / "clean.py").write_text("print('clean')", encoding="utf-8")

    repo2 = tmp_path / "repo2"
    repo2.mkdir()
    (repo2 / "leak.py").write_text("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8")

    # Run default text output (no --format json or sarif)
    result = runner.invoke(main, ["scan", "--repos", f"{repo1},{repo2}"])

    # Must exit 1 due to findings, and MUST NOT crash with TypeError
    assert result.exit_code == 1
    assert "TypeError" not in result.output
    assert "print_scan_findings() got an unexpected keyword argument" not in result.output

    # Verify both summary and findings are rendered
    assert "Multi-Repo Scan Summary" in result.output or "Multi-Repository" in result.output
    assert "repo1" in result.output
    assert "repo2" in result.output
    assert "AKIA" in result.output


def test_bug_b_print_scan_findings_direct_kwargs(capsys):
    """Bug B: print_scan_findings accepts files_scanned and files_skipped as kwargs directly."""
    finding = ScanFinding(
        rule_id="test-rule",
        rule_name="Test Rule",
        severity="HIGH",
        file_path="foo.py",
        line_number=1,
        raw_value="secret123",
        masked_value="sec••••••",
        fingerprint="sha256:abc",
    )

    # Call with direct kwargs
    print_scan_findings(
        [finding],
        title="Direct Kwargs Test",
        files_scanned=5,
        files_skipped=1,
    )
    captured = capsys.readouterr()
    assert "Files scanned: 5" in captured.out or "5" in captured.out
    assert "foo.py" in captured.out
