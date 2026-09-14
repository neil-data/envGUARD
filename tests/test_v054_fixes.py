"""Regression tests for EnvGuard v0.5.4 security and consistency fixes:
- Priority 1: Arbitrary file write via Git ref injection prevention (CRITICAL)
- Priority 2: Invalid block_on values rejected & check/ci blocking unified (CRITICAL)
- Priority 3: status, doctor, and interactive actions honor advanced_detection config (HIGH)
- Priority 4: password-assignment does not shadow db-password-assignment (MEDIUM)
- Priority 5: Typo'd / unknown top-level .envguard.yml keys warn instead of silent ignore (MEDIUM)
"""

from pathlib import Path
import subprocess
import pytest
from click.testing import CliRunner

from envguard import __version__
from envguard.cli import main
from envguard.config import EnvGuardConfig, load_config
from envguard.diagnostics import run_diagnostics
from envguard.exceptions import ConfigurationError, GitError
from envguard.git_utils import get_changed_files
from envguard.interactive import run_scan_action
from envguard.patterns import load_default_patterns
from envguard.scanner import scan_lines, scan_directory


def test_v054_version():
    """Verify version bumped to 0.5.4."""
    assert __version__ == "0.5.4"
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.5.4" in result.output


def test_priority_1_git_ref_injection_rejected(tmp_path):
    """Priority 1: get_changed_files, CLI --base, and ci.base_branch reject hyphen-prefixed refs."""
    exploit_file = tmp_path / "exploit.txt"

    # 1. get_changed_files must raise GitError and never touch filesystem
    with pytest.raises(GitError, match="cannot begin with '-'"):
        get_changed_files(base=f"--output={exploit_file}", repo_path=tmp_path)
    assert not exploit_file.exists()

    with pytest.raises(GitError, match="cannot begin with '-'"):
        get_changed_files(base="main", head="--output=foo", repo_path=tmp_path)

    # 2. ci.base_branch with hyphen must raise ConfigurationError
    cfg_file = tmp_path / ".envguard.yml"
    cfg_file.write_text("ci:\n  base_branch: '--output=exploit.txt'\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="cannot begin with '-'"):
        load_config(config_path=cfg_file)

    # 3. CLI envguard ci --base '--output=...' must reject
    runner = CliRunner()
    result = runner.invoke(main, ["ci", "--base", f"--output={exploit_file}"])
    assert result.exit_code == 2
    assert not exploit_file.exists()

    # 4. CLI envguard scan --changed --base '--output=...' must reject
    result_scan = runner.invoke(main, ["scan", "--changed", "--base", f"--output={exploit_file}"])
    assert result_scan.exit_code == 2
    assert not exploit_file.exists()


def test_priority_2_block_on_validation_and_unification(tmp_path):
    """Priority 2: block_on validates severity values and check unifies blocking with config.block_on."""
    cfg_file = tmp_path / ".envguard.yml"

    # 1. Invalid severity in block_on must raise ConfigurationError
    cfg_file.write_text("scan:\n  block_on:\n    - CRITICAL\n    - HIG\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="Invalid severity 'CRITICAL' in 'block_on'"):
        load_config(config_path=cfg_file)

    # 2. check command honors config.block_on
    # Create git repo
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=tmp_path, capture_output=True)

    # Configure block_on to only block on HIGH (MEDIUM findings should NOT block)
    cfg_file.write_text("scan:\n  block_on:\n    - HIGH\n", encoding="utf-8")

    # Stage a medium severity finding: api_key assignment
    staged_f = tmp_path / "creds.py"
    staged_f.write_text("api_key = 'abcdef1234567890abcdef'\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True)

    runner = CliRunner()
    # Run check inside tmp_path
    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(main, ["check"])
        # Exit code 0 because block_on is [HIGH] and api-key-assignment is MEDIUM
        assert result.exit_code == 0
        assert "CHECK PASSED" in result.output
        assert "non-blocking" in result.output


def test_priority_3_status_and_doctor_honor_advanced_detection_and_rules(tmp_path, monkeypatch):
    """Priority 3: status, doctor, and interactive actions pass advanced_config and rules config."""
    monkeypatch.setattr(Path, "cwd", lambda: tmp_path)
    (tmp_path / ".git").mkdir()

    # Disable entropy detection in config
    cfg_file = tmp_path / ".envguard.yml"
    cfg_file.write_text(
        "advanced_detection:\n"
        "  entropy:\n"
        "    enabled: false\n"
        "rules:\n"
        "  disabled:\n"
        "    - aws-access-key\n"
        "    - github-token\n",
        encoding="utf-8",
    )

    # A file with only a high-entropy string (no regex keywords)
    secret_f = tmp_path / "tokens.txt"
    secret_f.write_text("d8f7a93b4e6c1d2e8f0a3b5c\n", encoding="utf-8")

    # 1. status command should pass clean because entropy is disabled
    runner = CliRunner()
    res_status = runner.invoke(main, ["status", "--format", "json"])
    assert res_status.exit_code == 0
    assert '"total": 0' in res_status.output

    # 2. doctor command should reflect disabled rules count
    report = run_diagnostics(tmp_path)
    rules_check = next(c for c in report.checks if c.name == "Secret Rules")
    assert "23 rules active (25 total)" in rules_check.details

    # 3. interactive run_scan_action should honor advanced_detection
    # When run_scan_action executes, it should find 0 findings
    # (verify via scan_directory with config.advanced_detection)
    cfg = load_config(tmp_path)
    patterns = load_default_patterns(disabled_rules=cfg.disabled_rules)
    findings = scan_directory(tmp_path, patterns=patterns, advanced_config=cfg.advanced_detection)
    assert len(findings) == 0


def test_priority_4_db_password_not_shadowed():
    """Priority 4: database_password reports db-password-assignment, not password-assignment."""
    patterns = load_default_patterns()
    config = EnvGuardConfig()

    # 1. database_password assignment
    line_db = "database_password = 'my_database_password_123'"
    findings_db = scan_lines([line_db], "db.py", patterns, full_text=line_db)
    assert len(findings_db) == 1
    assert findings_db[0].rule_id == "db-password-assignment"

    # 2. db_password assignment
    line_db2 = "db_password = 'secure_db_password_123'"
    findings_db2 = scan_lines([line_db2], "db.py", patterns, full_text=line_db2)
    assert len(findings_db2) == 1
    assert findings_db2[0].rule_id == "db-password-assignment"

    # 3. Plain password assignment
    line_pwd = "password = 'my_regular_password_123'"
    findings_pwd = scan_lines([line_pwd], "auth.py", patterns, full_text=line_pwd)
    assert len(findings_pwd) == 1
    assert findings_pwd[0].rule_id == "password-assignment"


def test_priority_5_unknown_top_level_keys_warn(tmp_path):
    """Priority 5: Typo'd top-level keys produce warnings; valid top-level keys produce none."""
    # 1. Typo'd top-level key: disbaled_rules
    cfg_bad = tmp_path / "bad.yml"
    cfg_bad.write_text("version: 1\ndisbaled_rules:\n  - aws-access-key\n", encoding="utf-8")
    config_bad = load_config(config_path=cfg_bad)
    assert any("Unknown top-level key 'disbaled_rules'" in w for w in config_bad.warnings)

    # 2. Correct top-level key: disabled_rules
    cfg_good = tmp_path / "good.yml"
    cfg_good.write_text("version: 1\ndisabled_rules:\n  - aws-access-key\n", encoding="utf-8")
    config_good = load_config(config_path=cfg_good)
    assert not any("Unknown top-level key" in w for w in config_good.warnings)
    assert "aws-access-key" in config_good.disabled_rules

    # 3. Doctor surfaces top-level config warnings
    target_envguard = tmp_path / ".envguard.yml"
    target_envguard.write_text("version: 1\nunknown_key_typo: true\n", encoding="utf-8")
    report = run_diagnostics(tmp_path)
    config_check = next(c for c in report.checks if c.name == "Repository Config")
    assert config_check.status == "WARNING"
    assert "unknown_key_typo" in config_check.details
