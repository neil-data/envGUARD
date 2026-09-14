"""Regression tests for EnvGuard v0.5.5 micro patch update:
- Bug #1: Fix TypeError in Console.print() with file=sys.stderr across verbose mode
- Bug #2: Surface .envguard.yml config warnings in plain status command (align with doctor)
"""

import json
import os
from pathlib import Path
import pytest
from click.testing import CliRunner

from envguard import __version__
from envguard.cli import main
from envguard.diagnostics import run_diagnostics


@pytest.fixture
def runner():
    return CliRunner()


def test_version_bump_v055(runner):
    """Verify version bumped to at least 0.5.5."""
    assert __version__ >= "0.5.5"
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "envguard" in result.output.lower()


def test_bug_1_status_verbose_no_type_error(tmp_path, runner):
    """Bug #1: envguard status -v must not crash with TypeError."""
    cfg = tmp_path / ".envguard.yml"
    cfg.write_text("version: 1\nunknown_custom_key: true\n", encoding="utf-8")

    orig = os.getcwd()
    try:
        os.chdir(tmp_path)
        # Test short flag -v
        res_short = runner.invoke(main, ["status", "-v"], catch_exceptions=False)
        assert res_short.exit_code == 0
        assert "TypeError" not in res_short.output
        assert "unknown_custom_key" in res_short.output

        # Test long flag --verbose
        res_long = runner.invoke(main, ["status", "--verbose"], catch_exceptions=False)
        assert res_long.exit_code == 0
        assert "TypeError" not in res_long.output
        assert "unknown_custom_key" in res_long.output
    finally:
        os.chdir(orig)


def test_bug_1_scan_ci_check_verbose_with_warnings(tmp_path, runner):
    """Bug #1: scan, ci, and check in verbose mode must not crash when config warnings exist."""
    cfg = tmp_path / ".envguard.yml"
    cfg.write_text("version: 1\ntypo_option: test\n", encoding="utf-8")

    orig = os.getcwd()
    try:
        os.chdir(tmp_path)
        # scan -v
        res_scan = runner.invoke(main, ["scan", "-v"], catch_exceptions=False)
        assert res_scan.exit_code == 0
        assert "TypeError" not in res_scan.output
        assert "typo_option" in res_scan.output

        # check -v (not in git repo, handles error gracefully without crash)
        res_check = runner.invoke(main, ["check", "-v"])
        assert "TypeError" not in res_check.output

        # ci -v --all
        res_ci = runner.invoke(main, ["ci", "-v", "--all"], catch_exceptions=False)
        assert res_ci.exit_code == 0
        assert "TypeError" not in res_ci.output
        assert "typo_option" in res_ci.output
    finally:
        os.chdir(orig)


def test_bug_2_status_plain_surfaces_config_warnings(tmp_path, runner):
    """Bug #2: envguard status (plain, no flags) surfaces config warnings and marks configuration as WARNING."""
    cfg = tmp_path / ".envguard.yml"
    cfg.write_text("version: 1\nunknown_typo_key: true\n", encoding="utf-8")

    orig = os.getcwd()
    try:
        os.chdir(tmp_path)
        result = runner.invoke(main, ["status"], catch_exceptions=False)
        assert result.exit_code == 0
        # Must show the config warning
        assert "Config warning:" in result.output
        assert "unknown_typo_key" in result.output
        # Dashboard table must show WARNING for Configuration
        assert "WARNING (.envguard.yml)" in result.output
        # Overall status must not be silently SECURE
        assert "SECURE" not in result.output
        assert "configuration warning" in result.output
    finally:
        os.chdir(orig)


def test_bug_2_status_and_doctor_agree_on_config_warning(tmp_path, runner):
    """Bug #2: doctor and status both report config warning for the same unrecognized key."""
    cfg = tmp_path / ".envguard.yml"
    cfg.write_text("version: 1\nunrecognized_key_xyz: 123\n", encoding="utf-8")

    orig = os.getcwd()
    try:
        os.chdir(tmp_path)
        # Doctor report
        report = run_diagnostics(tmp_path)
        config_check = next(c for c in report.checks if c.name == "Repository Config")
        assert config_check.status == "WARNING"
        assert "unrecognized_key_xyz" in config_check.details

        # Status command
        res_status = runner.invoke(main, ["status"], catch_exceptions=False)
        assert res_status.exit_code == 0
        assert "unrecognized_key_xyz" in res_status.output
        assert "WARNING (.envguard.yml)" in res_status.output
    finally:
        os.chdir(orig)


def test_bug_2_status_json_includes_config_warnings(tmp_path, runner):
    """Bug #2: envguard status --format json includes config_warnings and configuration status."""
    cfg = tmp_path / ".envguard.yml"
    cfg.write_text("version: 1\nbad_key: value\n", encoding="utf-8")

    orig = os.getcwd()
    try:
        os.chdir(tmp_path)
        res_json = runner.invoke(main, ["status", "--format", "json"], catch_exceptions=False)
        assert res_json.exit_code == 0
        data = json.loads(res_json.output)

        assert data["command"] == "status"
        assert "config_warnings" in data
        assert len(data["config_warnings"]) > 0
        assert any("bad_key" in w for w in data["config_warnings"])
        assert data["checks"]["configuration"]["status"] == "warning"
        assert any("bad_key" in w for w in data["checks"]["configuration"]["warnings"])
    finally:
        os.chdir(orig)
