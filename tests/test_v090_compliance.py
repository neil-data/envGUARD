"""Tests for Compliance framework mapping engine (v0.9.0)."""

from envguard.compliance import (
    load_compliance_mappings,
    get_rule_compliance,
    map_findings_to_compliance,
    COMPLIANCE_DISCLAIMER,
)
from envguard.scanner import ScanFinding


def test_load_compliance_schema():
    data = load_compliance_mappings()
    assert data.get("schema_version") == 1
    assert "rule_mappings" in data
    assert "frameworks" in data
    assert "soc2" in data["frameworks"]
    assert "iso27001" in data["frameworks"]
    assert len(data["rule_mappings"]) >= 25


def test_rule_compliance_mapping():
    c = get_rule_compliance("aws-access-key")
    assert c is not None
    assert "CC6.1" in c["controls"]["soc2"]
    assert "A.8.24" in c["controls"]["iso27001"]

    c_slack = get_rule_compliance("slack-token")
    assert c_slack is not None
    assert "CC6.6" in c_slack["controls"]["soc2"]


def test_map_findings_to_compliance():
    f1 = ScanFinding(
        rule_id="aws-access-key",
        rule_name="AWS Access Key",
        severity="HIGH",
        file_path="src/config.py",
        line_number=10,
        raw_value="AKIAIOSFODNN7EXAMPLE",
        masked_value="AKIA************MPLE",
        fingerprint="fp1",
    )
    f2 = ScanFinding(
        rule_id="stripe-secret-key",
        rule_name="Stripe Secret Key",
        severity="HIGH",
        file_path="src/api.py",
        line_number=12,
        raw_value="MOCKED_STRIPE_KEY_SAMPLE",
        masked_value="MOCK************MPLE",
        fingerprint="fp2",
    )

    summary = map_findings_to_compliance([f1, f2])
    assert summary.total_impacted_controls > 0
    assert "CC6.1" in summary.soc2_controls
    assert summary.soc2_controls["CC6.1"].findings_count >= 1
    assert "aws-access-key" in summary.soc2_controls["CC6.1"].affected_rules
    assert summary.disclaimer == COMPLIANCE_DISCLAIMER
