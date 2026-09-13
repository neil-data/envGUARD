"""Unit tests verifying false positive filtering for hashes, UUIDs, checksums, and placeholders."""

from pathlib import Path
from envguard.patterns import load_default_patterns
from envguard.scanner import scan_lines, scan_text


def test_false_positive_fixtures_are_not_flagged(patterns):
    fixture_path = Path("tests/fixtures/false_positives.txt")
    if not fixture_path.exists():
        return
    text = fixture_path.read_text(encoding="utf-8")
    findings = scan_text(text, "tests/fixtures/false_positives.txt", patterns)
    # None of the benign hashes, UUIDs, or placeholders should be flagged as HIGH or MEDIUM
    severe_findings = [f for f in findings if f.severity in ("HIGH", "MEDIUM")]
    assert len(severe_findings) == 0


def test_hashes_fixture_not_flagged(patterns):
    fixture_path = Path("tests/fixtures/hashes.txt")
    if not fixture_path.exists():
        return
    text = fixture_path.read_text(encoding="utf-8")
    findings = scan_text(text, "tests/fixtures/hashes.txt", patterns)
    severe_findings = [f for f in findings if f.severity in ("HIGH", "MEDIUM")]
    assert len(severe_findings) == 0


def test_common_placeholders_not_flagged(patterns):
    samples = [
        "API_KEY=your_api_key_here",
        "SECRET_KEY=CHANGEME",
        "DATABASE_PASSWORD=replace_with_your_password",
        "ACCESS_TOKEN=dummy_token_value",
        "AUTH_TOKEN=insert_token_here",
    ]
    for s in samples:
        findings = scan_text(s, "app.env", patterns)
        assert len(findings) == 0, f"Expected zero findings for placeholder '{s}', got {findings}"
