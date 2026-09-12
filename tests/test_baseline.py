"""Tests for baseline creation and suppression (.envguard-baseline.json)."""

import json
from pathlib import Path
import pytest

from envguard.baseline import (
    create_baseline,
    filter_baseline_findings,
    load_baseline,
)
from envguard.exceptions import BaselineError
from envguard.scanner import ScanFinding, compute_fingerprint


def make_finding(rule_id: str, file_path: str, raw_secret: str, line: int = 1) -> ScanFinding:
    fp = compute_fingerprint(rule_id, file_path, raw_secret)
    return ScanFinding(
        rule_id=rule_id,
        rule_name=rule_id.replace("-", " ").title(),
        severity="HIGH",
        file_path=file_path,
        line_number=line,
        raw_value=raw_secret,
        masked_value="MASKED",
        fingerprint=fp,
    )


def test_baseline_creation_and_no_plaintext_secrets(tmp_path):
    output_path = tmp_path / ".envguard-baseline.json"
    fake_raw_secret = "AKIAIOSFODNN7EXAMPLE"
    dummy_stripe = "".join(["sk_", "test_", "123456789012345678901234"])
    findings = [
        make_finding("aws-access-key", "config.py", fake_raw_secret, line=10),
        make_finding("stripe-secret-key", "pay.py", dummy_stripe, line=20),
    ]

    count = create_baseline(findings, output_path=output_path)
    assert count == 2
    assert output_path.is_file()

    content = output_path.read_text(encoding="utf-8")
    data = json.loads(content)

    assert data["version"] == 1
    assert data["total_findings"] == 2
    assert len(data["findings"]) == 2

    # SECURITY INVARIANT: Raw secrets MUST NEVER exist in baseline file
    assert fake_raw_secret not in content
    assert dummy_stripe not in content

    # Check structure
    for item in data["findings"]:
        assert "fingerprint" in item
        assert item["fingerprint"].startswith("sha256:")
        assert "rule_id" in item
        assert "file" in item


def test_baseline_overwrite_safety(tmp_path):
    output_path = tmp_path / ".envguard-baseline.json"
    findings = [make_finding("aws-access-key", "config.py", "AKIAIOSFODNN7EXAMPLE")]

    # First write succeeds
    create_baseline(findings, output_path=output_path)

    # Second write without overwrite fails
    with pytest.raises(BaselineError) as exc_info:
        create_baseline(findings, output_path=output_path, overwrite=False)
    assert "already exists" in str(exc_info.value)

    # Second write with overwrite succeeds
    create_baseline(findings, output_path=output_path, overwrite=True)


def test_baseline_filters_known_and_identifies_new(tmp_path):
    baseline_file = tmp_path / ".envguard-baseline.json"
    secret_1 = "AKIAIOSFODNN7EXAMPLE"
    secret_2 = "".join(["sk_", "test_", "123456789012345678901234"])
    secret_new = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"

    f1 = make_finding("aws-access-key", "config.py", secret_1)
    f2 = make_finding("stripe-secret-key", "pay.py", secret_2)
    create_baseline([f1, f2], output_path=baseline_file)

    loaded_fps = load_baseline(baseline_file)
    assert len(loaded_fps) == 2

    # Now scan finds f1 (known), f2 (known), and f3 (new)
    f3 = make_finding("github-token", "deploy.py", secret_new)
    current_findings = [f1, f2, f3]

    new_findings, suppressed = filter_baseline_findings(current_findings, loaded_fps)

    assert len(new_findings) == 1
    assert new_findings[0].rule_id == "github-token"
    assert len(suppressed) == 2
    assert {s.rule_id for s in suppressed} == {"aws-access-key", "stripe-secret-key"}
