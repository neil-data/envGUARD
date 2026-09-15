"""Tests for EnvGuard v0.7.0 IDE Diagnostic JSON format."""

import json
from pathlib import Path
import pytest
from click.testing import CliRunner

from envguard import __version__
from envguard.cli import main
from envguard.reporter import render_ide_json
from envguard.scanner import ScanFinding, scan_directory


@pytest.fixture
def runner():
    return CliRunner()


def test_ide_json_schema_structure(tmp_path):
    """Verify render_ide_json produces required schema fields and types."""
    slack_val = "xox" + "b-123456789012-1234567890123-abcdefghijklmnopqrstuvwx"
    masked_val = "xox" + "b-••••••••••••••••••••••••••••••••••••••••••••••••"
    finding = ScanFinding(
        rule_id="slack-token",
        rule_name="Slack Token",
        severity="HIGH",
        file_path="src/bot.py",
        line_number=10,
        raw_value=slack_val,
        masked_value=masked_val,
        fingerprint="sha256:abc123def456",
        line_snippet=f"TOKEN = '{slack_val}'",
        column=10,
        end_column=65,
    )

    out_file = tmp_path / "ide_report.json"
    render_ide_json([finding], output_path=out_file)

    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert data["tool"] == "envguard"
    assert data["version"] == __version__
    assert data["status"] == "failed"
    assert data["total_findings"] == 1

    f_out = data["findings"][0]
    assert f_out["file"] == "src/bot.py"
    assert f_out["line"] == 10
    assert f_out["column"] == 10
    assert f_out["end_line"] == 10
    assert f_out["end_column"] == 65
    assert f_out["severity"] == "HIGH"
    assert f_out["rule_id"] == "slack-token"
    assert f_out["rule_name"] == "Slack Token"
    assert "Secret detected" in f_out["message"]
    assert f_out["masked_value"] == masked_val
    # Plaintext secret MUST NOT be leaked
    assert slack_val not in json.dumps(data)


def test_ide_json_fallback_coordinates(tmp_path):
    """Verify safe fallback (1-based min 1) when column coordinates are None."""
    finding = ScanFinding(
        rule_id="generic-secret",
        rule_name="Generic Secret",
        severity="MEDIUM",
        file_path="config.yml",
        line_number=0,  # invalid line number should clamp to 1
        raw_value="mysecret",
        masked_value="my••••••",
        fingerprint="sha256:11112222",
        column=None,
        end_column=None,
    )

    out_file = tmp_path / "ide_fallback.json"
    render_ide_json([finding], output_path=out_file)

    data = json.loads(out_file.read_text(encoding="utf-8"))
    f_out = data["findings"][0]
    assert f_out["line"] >= 1
    assert f_out["column"] >= 1
    assert f_out["end_line"] >= 1
    assert f_out["end_column"] >= 1


def test_cli_scan_ide_format(runner, tmp_path):
    """Verify 'envguard scan --format ide' produces schema-compliant JSON via CLI."""
    stripe_val = "sk_" + "live_" + "abcdef1234567890abcdef1234"
    secret_file = tmp_path / "secret.env"
    secret_file.write_text(f"STRIPE_KEY={stripe_val}\n", encoding="utf-8")

    res = runner.invoke(main, ["scan", str(tmp_path), "--format", "ide"])
    assert res.exit_code == 1
    data = json.loads(res.output)
    assert data["schema_version"] == 1
    assert data["tool"] == "envguard"
    assert data["status"] == "failed"
    assert data["total_findings"] >= 1

    finding = data["findings"][0]
    assert finding["line"] == 1
    assert finding["column"] >= 1
    assert finding["end_column"] > finding["column"]
    assert finding["masked_value"].startswith("sk_l")
    # Raw value must not be in output
    assert stripe_val not in res.output


def test_cli_scan_ide_clean(runner, tmp_path):
    """Verify 'envguard scan --format ide' on clean repo returns passed status."""
    clean_file = tmp_path / "hello.py"
    clean_file.write_text("print('All clean')\n", encoding="utf-8")

    res = runner.invoke(main, ["scan", str(tmp_path), "--format", "ide"])
    assert res.exit_code == 0
    data = json.loads(res.output)
    assert data["schema_version"] == 1
    assert data["status"] == "passed"
    assert data["total_findings"] == 0
    assert data["findings"] == []
