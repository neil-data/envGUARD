"""Tests for generic output file writing and CI format reporting."""

import json
from pathlib import Path
from click.testing import CliRunner
import pytest

from envguard.cli import main


def test_scan_output_json_file(tmp_path):
    """Verify envguard scan --format json --output writes valid JSON."""
    test_file = tmp_path / "secret.py"
    test_file.write_text("API_KEY = 'AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8")
    output_file = tmp_path / "out" / "report.json"

    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--format", "json", "--output", str(output_file)])
    assert result.exit_code == 1  # Finding detected
    assert output_file.is_file()

    data = json.loads(output_file.read_text(encoding="utf-8"))
    assert data["command"] == "scan"
    assert data["status"] == "failed"
    assert data["summary"]["total"] >= 1


def test_scan_output_sarif_file(tmp_path):
    """Verify envguard scan --format sarif --output writes valid SARIF 2.1.0."""
    test_file = tmp_path / "secret.py"
    test_file.write_text("API_KEY = 'AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8")
    output_file = tmp_path / "out" / "results.sarif"

    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--format", "sarif", "--output", str(output_file)])
    assert result.exit_code == 1
    assert output_file.is_file()

    sarif = json.loads(output_file.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) >= 1


def test_ci_command_all_sarif_output(tmp_path):
    """Verify envguard ci --all --format sarif --output works cleanly."""
    test_file = tmp_path / "code.py"
    test_file.write_text("# safe code\n", encoding="utf-8")
    out_file = tmp_path / "ci_reports" / "summary.sarif"

    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(main, ["ci", "--all", "--format", "sarif", "--output", str(out_file)])
        assert result.exit_code == 0
        assert out_file.is_file()
        sarif = json.loads(out_file.read_text(encoding="utf-8"))
        assert len(sarif["runs"][0]["results"]) == 0


def test_ci_command_text_output(tmp_path):
    """Verify envguard ci --format text --output writes plain text report."""
    out_file = tmp_path / "ci_reports" / "summary.txt"
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(main, ["ci", "--all", "--format", "text", "--output", str(out_file)])
        assert result.exit_code == 0
        assert out_file.is_file()
        text = out_file.read_text(encoding="utf-8")
        assert "EnvGuard CI Scan" in text
        assert "Result Status:" in text
