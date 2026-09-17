"""Tests for envguard lint-config command (v0.9.0)."""

from pathlib import Path
import re
from click.testing import CliRunner
import pytest

from envguard.cli import main
from envguard.config_linter import lint_configuration, check_env_git_risk


def test_lint_config_clean(tmp_path: Path):
    cfg = tmp_path / ".envguard.yml"
    cfg.write_text("""
version: 1
scan:
  max_file_size_mb: 5
rules:
  disabled:
    - aws-access-key
""", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["lint-config", str(tmp_path)])
    assert result.exit_code == 0
    assert "CONFIGURATION ASSURANCE: PASS" in result.output


def test_lint_config_unknown_keys(tmp_path: Path):
    cfg = tmp_path / ".envguard.yml"
    cfg.write_text("""
version: 1
min_serverity: HIGH
unknown_top_level: true
""", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["lint-config", str(tmp_path)])
    assert result.exit_code == 0  # warnings only
    assert "Unknown" in result.output
    assert "min_serverity" in result.output


def test_lint_config_invalid_rule_id(tmp_path: Path):
    cfg = tmp_path / ".envguard.yml"
    cfg.write_text("""
version: 1
rules:
  disabled:
    - NONEXISTENT_RULE_ID
""", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["lint-config", str(tmp_path)])
    assert result.exit_code == 0  # warning
    assert "NONEXISTENT_RU" in result.output


def test_lint_config_conflicting_settings(tmp_path: Path):
    cfg = tmp_path / ".envguard.yml"
    cfg.write_text("""
version: 1
rules:
  disabled:
    - aws-access-key
  severity_overrides:
    aws-access-key: LOW
""", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["lint-config", str(tmp_path)])
    assert result.exit_code == 1
    assert "cannot be" in result.output
    assert re.search(r"both\s+disabled", result.output) or ("both" in result.output and "disabled" in result.output)


def test_lint_config_org_override_conflict(tmp_path: Path):
    org = tmp_path / ".envguard-org.yml"
    org.write_text("""
version: 1
rules:
  disabled: []
""", encoding="utf-8")

    cfg = tmp_path / ".envguard.yml"
    cfg.write_text("""
version: 1
rules:
  disabled:
    - aws-access-key
""", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["lint-config", str(tmp_path)])
    assert result.exit_code == 1
    assert "enforced by" in result.output


def test_lint_config_json_format(tmp_path: Path):
    cfg = tmp_path / ".envguard.yml"
    cfg.write_text("""
version: 1
scan:
  max_file_size_mb: 5
""", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["lint-config", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0
    assert '"command": "lint-config"' in result.output
    assert '"clean": true' in result.output
