"""Tests for structured JSON output formatting across CLI commands."""

import json
from pathlib import Path
from click.testing import CliRunner
import pytest

from envguard.cli import main


@pytest.fixture
def runner():
    return CliRunner()


def test_scan_json_output_clean(runner, tmp_path):
    # Empty directory scan in JSON mode
    clean_file = tmp_path / "hello.py"
    clean_file.write_text("print('hello world')\n", encoding="utf-8")

    result = runner.invoke(main, ["scan", "--path", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0

    data = json.loads(result.output)
    assert data["schema_version"] == 1
    assert data["envguard_version"] == "0.3.0"
    assert data["command"] == "scan"
    assert data["status"] == "passed"
    assert data["summary"]["total"] == 0
    assert data["findings"] == []


def test_scan_json_output_with_findings(runner, tmp_path):
    secret_file = tmp_path / "creds.py"
    secret_val = "AKIAIOSFODNN7EXAMPLE"
    secret_file.write_text(f"AWS_KEY = '{secret_val}'\n", encoding="utf-8")

    result = runner.invoke(main, ["scan", "--path", str(tmp_path), "--format", "json"])
    assert result.exit_code == 1

    data = json.loads(result.output)
    assert data["schema_version"] == 1
    assert data["command"] == "scan"
    assert data["status"] == "failed"
    assert data["summary"]["high"] >= 1
    assert len(data["findings"]) >= 1

    # Security Check: Full secret MUST be masked in JSON output
    first_finding = data["findings"][0]
    assert first_finding["rule_id"] == "aws-access-key"
    assert first_finding["severity"] == "HIGH"
    assert secret_val not in first_finding["masked_value"]
    assert "AKIA" in first_finding["masked_value"]
    assert "••••" in first_finding["masked_value"]


def test_diff_json_output(runner, tmp_path):
    env_file = tmp_path / ".env"
    example_file = tmp_path / ".env.example"

    env_file.write_text("DATABASE_URL=postgres://...\nREDIS_URL=redis://...\n", encoding="utf-8")
    example_file.write_text("DATABASE_URL=\nOLD_KEY=\n", encoding="utf-8")

    result = runner.invoke(
        main,
        ["diff", "--env", str(env_file), "--example", str(example_file), "--format", "json"],
    )
    assert result.exit_code == 1

    data = json.loads(result.output)
    assert data["schema_version"] == 1
    assert data["command"] == "diff"
    assert data["status"] == "failed"
    assert data["has_drift"] is True
    assert data["missing_from_example"] == ["REDIS_URL"]
    assert data["extra_in_example"] == ["OLD_KEY"]


def test_status_json_output(runner, tmp_path):
    result = runner.invoke(main, ["status", "--format", "json"])
    assert result.exit_code == 0

    data = json.loads(result.output)
    assert data["schema_version"] == 1
    assert data["command"] == "status"
    assert "overall_status" in data
    assert "checks" in data
    assert "is_git_repository" in data["checks"]
    assert "env_file_tracked" in data["checks"]
