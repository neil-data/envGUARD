"""Tests for SARIF 2.1.0 generation module (envguard/sarif.py)."""

import json
from envguard.patterns import load_default_patterns
from envguard.sarif import generate_sarif
from envguard.scanner import ScanFinding


def test_sarif_structure_and_schema():
    """Verify SARIF 2.1.0 schema, version, and tool driver metadata."""
    patterns = load_default_patterns()
    raw_secret = "AKIAIOSFODNN7EXAMPLE"
    findings = [
        ScanFinding(
            rule_id="aws-access-key-id",
            rule_name="AWS Access Key ID",
            severity="HIGH",
            file_path="src/config.py",
            line_number=18,
            raw_value=raw_secret,
            masked_value="AKIA••••••••••••MPLE",
            fingerprint="sha256:abc123def456",
            line_snippet="AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'",
        )
    ]

    sarif = generate_sarif(findings, tool_version="0.5.0", patterns=patterns)

    # Validate high-level fields
    assert sarif["version"] == "2.1.0"
    assert "sarif-2.1.0.json" in sarif["$schema"]
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "EnvGuard"
    assert driver["semanticVersion"] == "0.5.0"
    assert "https://github.com/neil-data/envGUARD" in driver["informationUri"]
    assert len(driver["rules"]) > 0

    # Validate result mapping
    results = run["results"]
    assert len(results) == 1
    res = results[0]
    assert res["ruleId"] == "aws-access-key-id"
    assert res["level"] == "error"  # HIGH maps to error
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/config.py"
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 18

    # CRITICAL: Verify NO plaintext secret appears anywhere in SARIF text
    sarif_json = json.dumps(sarif)
    assert raw_secret not in sarif_json
    assert res["properties"]["maskedValue"] == "AKIA••••••••••••MPLE"
    assert "AKIA" in sarif_json



def test_sarif_severity_mappings():
    """Verify HIGH -> error, MEDIUM -> warning, LOW -> note."""
    findings = [
        ScanFinding("rule-h", "Rule H", "HIGH", "f1.py", 1, "raw1", "masked1", "fp1"),
        ScanFinding("rule-m", "Rule M", "MEDIUM", "f2.py", 2, "raw2", "masked2", "fp2"),
        ScanFinding("rule-l", "Rule L", "LOW", "f3.py", 3, "raw3", "masked3", "fp3"),
    ]

    sarif = generate_sarif(findings, tool_version="0.5.0")
    results = sarif["runs"][0]["results"]
    assert results[0]["level"] == "error"
    assert results[1]["level"] == "warning"
    assert results[2]["level"] == "note"
