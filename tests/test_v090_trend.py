"""Tests for Historical Trend engine (v0.9.0)."""

import json
from pathlib import Path

from envguard.scanner import ScanFinding
from envguard.trend import compute_baseline_trend


def test_trend_no_baseline(tmp_path: Path):
    findings = [
        ScanFinding("aws-access-key", "AWS Key", "HIGH", "test.py", 1, "raw", "masked", fingerprint="fp1"),
    ]
    report = compute_baseline_trend(findings, tmp_path / "nonexistent.json")
    assert not report.baseline_exists
    assert report.baseline_count == 0
    assert report.current_count == 1
    assert len(report.new_findings) == 1
    assert report.trend_direction == "DEGRADING"


def test_trend_with_baseline(tmp_path: Path):
    base_file = tmp_path / ".envguard-baseline.json"
    base_payload = {
        "version": 1,
        "created_at": "2026-09-01T00:00:00Z",
        "total_findings": 2,
        "findings": [
            {"fingerprint": "fp1", "rule_id": "aws-access-key", "file": "app.py", "line": 5},
            {"fingerprint": "fp2", "rule_id": "github-token", "file": "app.py", "line": 8},
        ],
    }
    base_file.write_text(json.dumps(base_payload), encoding="utf-8")

    # Current codebase resolved fp2, kept fp1, and introduced fp3
    current_findings = [
        ScanFinding("aws-access-key", "AWS Key", "HIGH", "app.py", 5, "raw", "masked", fingerprint="fp1"),
        ScanFinding("slack-token", "Slack", "HIGH", "app.py", 15, "raw", "masked", fingerprint="fp3"),
    ]

    report = compute_baseline_trend(current_findings, base_file)
    assert report.baseline_exists
    assert report.baseline_count == 2
    assert report.current_count == 2
    assert len(report.persistent_findings) == 1
    assert report.persistent_findings[0].fingerprint == "fp1"
    assert len(report.new_findings) == 1
    assert report.new_findings[0].fingerprint == "fp3"
    assert report.resolved_count == 1  # fp2 was resolved
    assert report.remediation_rate_pct == 50.0
