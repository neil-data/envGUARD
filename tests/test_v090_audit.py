"""Tests for envguard audit command and report generation (v0.9.0)."""

import json
from pathlib import Path
from click.testing import CliRunner

from envguard.cli import main
from envguard.scanner import ScanFinding
from envguard.audit import build_audit_data, generate_html_audit_report, generate_audit_json


def test_audit_posture_grading(tmp_path: Path):
    # High finding yields Grade F
    high_findings = [
        ScanFinding("aws-access-key", "AWS Key", "HIGH", "app.py", 1, "raw", "masked", fingerprint="fp1"),
    ]
    data_f = build_audit_data(tmp_path, high_findings)
    assert data_f.posture_grade == "F"

    # Medium findings
    med_findings = [
        ScanFinding("high-entropy-string", "Entropy", "MEDIUM", "app.py", 1, "raw", "masked", fingerprint="fp1"),
    ]
    data_b = build_audit_data(tmp_path, med_findings)
    assert data_b.posture_grade == "B"

    # Clean yields Grade A+ or A- depending on local gitignore presence
    data_clean = build_audit_data(tmp_path, [])
    assert "A" in data_clean.posture_grade


def test_html_report_zero_plain_secrets(tmp_path: Path):
    raw_secret = "AKIAIOSFODNN7EXAMPLE_SECRET_VAL"
    finding = ScanFinding(
        rule_id="aws-access-key",
        rule_name="AWS Access Key",
        severity="HIGH",
        file_path="src/secret.py",
        line_number=4,
        raw_value=raw_secret,
        masked_value="AKIA************T_VAL",
        fingerprint="fp1",
    )
    data = build_audit_data(tmp_path, [finding])
    html_out = generate_html_audit_report(data)

    # Must contain masked representation
    assert finding.masked_value in html_out
    # MUST NOT contain raw unmasked secret!
    assert raw_secret not in html_out
    assert "@media print" in html_out
    assert "Compliance Notice" in html_out or "informational control cross-references" in html_out


def test_audit_cli_command(tmp_path: Path):
    py_file = tmp_path / "app.py"
    py_file.write_text("print('clean app')\n", encoding="utf-8")

    runner = CliRunner()
    res = runner.invoke(main, ["audit", str(tmp_path)])
    assert res.exit_code == 0
    assert "EnvGuard Compliance & Security Audit" in res.output

    # Test HTML export
    html_out = tmp_path / "audit.html"
    res_html = runner.invoke(main, ["audit", str(tmp_path), "--format", "html", "-o", str(html_out)])
    assert res_html.exit_code == 0
    assert html_out.is_file()
    assert "<!DOCTYPE html>" in html_out.read_text(encoding="utf-8")
