"""Comprehensive regression test suite for EnvGuard v0.9.9 precision and remediation safety.

Covers:
1. Bug #1: Generic high-entropy false positives (alphabets, paths, hashes, lockfiles, docs, fixtures, non-secret keys).
2. Bug #2: Duplicate fingerprint findings canonicalization and occurrences grouping across lines and files.
3. Bug #3: Remediation safety validation, refusal of non-secret targets, and zero .env pollution.
"""

import json
from pathlib import Path
import pytest

from envguard.baseline import create_baseline, filter_baseline_findings
from envguard.detectors import AdvancedDetectionConfig
from envguard.patterns import load_default_patterns
from envguard.remediation import (
    apply_remediation_plan,
    create_remediation_plan,
    validate_remediation_candidate,
)
from envguard.reporter import format_finding_dict
from envguard.sarif import generate_sarif
from envguard.scanner import (
    ScanFinding,
    compute_fingerprint,
    compute_legacy_fingerprint,
    deduplicate_findings,
    scan_directory,
    scan_lines,
    scan_text,
)


# ==============================================================================
# Bug #1: Generic High-Entropy False Positives
# ==============================================================================


def test_bug1_base58_alphabet_not_detected_as_secret():
    """Base58 or similar alphabet constants must not be flagged by generic-high-entropy-secret."""
    code = 'BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"\n'
    findings = scan_text(code, "crypto/base58.py", load_default_patterns())
    entropy_findings = [f for f in findings if f.rule_id == "generic-high-entropy-secret"]
    assert len(entropy_findings) == 0


def test_bug1_windows_paths_not_detected_as_secret():
    """Windows filesystem paths must not be flagged as generic high-entropy secrets."""
    code = (
        'EXE_PATH = "C:\\\\Users\\\\Neil\\\\AppData\\\\Local\\\\Programs\\\\Python\\\\Python311\\\\python.exe"\n'
        'UNC_PATH = "\\\\\\\\fileserver01\\\\share\\\\dept\\\\project\\\\data.bin"\n'
    )
    findings = scan_text(code, "config.py", load_default_patterns())
    entropy_findings = [f for f in findings if f.rule_id == "generic-high-entropy-secret"]
    assert len(entropy_findings) == 0


def test_bug1_non_secret_variable_names_not_detected():
    """QUEUE_KEY, TEST_KEY, REGISTRY_KEY, SEEN_HASHES_KEY must not produce generic findings."""
    code = (
        'QUEUE_KEY = "queue_worker_process_main_channel_prod_v2"\n'
        'TEST_KEY = "test_run_isolation_token_fixture_setup_12345"\n'
        'SEEN_HASHES_KEY = "seen_hashes_bucket_index_cache_v1"\n'
        'REGISTRY_KEY = "registry_service_lookup_entry_point_prod"\n'
    )
    findings = scan_text(code, "services/broker.py", load_default_patterns())
    for f in findings:
        assert f.rule_id not in ("generic-high-entropy-secret", "generic-secret")


def test_bug1_markdown_and_docs_exempt_from_entropy(tmp_path):
    """Documentation files (.md, .rst, .txt) must not trigger generic-high-entropy-secret."""
    doc_file = tmp_path / "README.md"
    doc_file.write_text(
        "# Project Overview\n\nSome hash-like identifier: 8f9a2b7c4e1d0f3a6b8c5d2e9f1a0b3c4d5e6f7a8b9c\n",
        encoding="utf-8",
    )
    findings = scan_directory(tmp_path)
    entropy_findings = [f for f in findings if f.rule_id == "generic-high-entropy-secret"]
    assert len(entropy_findings) == 0


def test_bug1_lockfile_exempt_from_entropy(tmp_path):
    """Lockfiles containing SRI hashes must not trigger generic-high-entropy-secret."""
    lock_file = tmp_path / "package-lock.json"
    lock_file.write_text(
        '{\n  "integrity": "sha512-8f9a2b7c4e1d0f3a6b8c5d2e9f1a0b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a=="\n}\n',
        encoding="utf-8",
    )
    findings = scan_directory(tmp_path)
    entropy_findings = [f for f in findings if f.rule_id == "generic-high-entropy-secret"]
    assert len(entropy_findings) == 0


def test_bug1_test_fixtures_exempt_from_entropy(tmp_path):
    """Files inside fixtures/ or testdata/ directories are exempt from generic entropy."""
    fix_dir = tmp_path / "fixtures"
    fix_dir.mkdir()
    fixture_file = fix_dir / "sample_data.json"
    fixture_file.write_text('{"token": "8f9a2b7c4e1d0f3a6b8c5d2e9f1a0b3c4d5e6f7a"}', encoding="utf-8")

    findings = scan_directory(tmp_path)
    entropy_findings = [f for f in findings if f.rule_id == "generic-high-entropy-secret"]
    assert len(entropy_findings) == 0


def test_bug1_genuine_high_entropy_secret_detected():
    """Genuine high-entropy secret assignments must still be detected."""
    code = 'CUSTOM_API_SECRET = "8f9a2b7c4e1d0f3a6b8c5d2e9f1a0b3c4d5e6f7a"\n'
    findings = scan_text(code, "services/auth.py", load_default_patterns())
    assert len(findings) > 0
    assert any("secret" in f.rule_id.lower() or "entropy" in f.rule_id.lower() for f in findings)


# ==============================================================================
# Bug #2: Duplicate Fingerprint Findings & Occurrences
# ==============================================================================


def test_bug2_deduplication_within_same_file():
    """An identical secret appearing on multiple lines should produce 1 finding with secondary occurrences."""
    code = (
        'TOKEN_1 = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"\n'
        '# Some other code\n'
        'TOKEN_2 = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"\n'
    )
    findings = scan_text(code, "app.py", load_default_patterns())
    assert len(findings) == 1
    primary = findings[0]
    assert primary.line_number == 1
    assert len(primary.occurrences) == 1
    assert primary.occurrences[0]["line_number"] == 3
    assert primary.occurrence_count == 2


def test_bug2_deduplication_across_multiple_files(tmp_path):
    """Identical secrets across multiple files should be grouped into a single logical finding."""
    f1 = tmp_path / "mod_a.py"
    f2 = tmp_path / "mod_b.py"
    secret_line = 'API_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
    f1.write_text(secret_line, encoding="utf-8")
    f2.write_text(secret_line, encoding="utf-8")

    findings = scan_directory(tmp_path)
    aws_findings = [f for f in findings if f.rule_id == "aws-access-key"]
    assert len(aws_findings) == 1
    primary = aws_findings[0]
    assert primary.occurrence_count == 2
    assert len(primary.occurrences) == 1


def test_bug2_single_occurrence_backward_compatibility():
    """Single-occurrence findings must have occurrences=[] and occurrence_count=1."""
    code = 'MY_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
    findings = scan_text(code, "config.py", load_default_patterns())
    assert len(findings) == 1
    f = findings[0]
    assert f.occurrences == []
    assert f.occurrence_count == 1

    d = format_finding_dict(f)
    assert "occurrences" not in d  # Single-occurrence dict is identical to previous versions


def test_bug2_canonical_fingerprint_deterministic():
    """Canonical fingerprints are deterministic and independent of file path."""
    fp1 = compute_fingerprint("aws-access-key", "AKIAIOSFODNN7EXAMPLE")
    fp2 = compute_fingerprint("aws-access-key", "any/file/path.py", "AKIAIOSFODNN7EXAMPLE")
    assert fp1 == fp2
    assert fp1.startswith("sha256:")


def test_bug2_baseline_backward_compatibility(tmp_path):
    """filter_baseline_findings handles both canonical and legacy path-based fingerprints."""
    raw_secret = "AKIAIOSFODNN7EXAMPLE"
    canonical_fp = compute_fingerprint("aws-access-key", raw_secret)
    legacy_fp = compute_legacy_fingerprint("aws-access-key", "legacy_file.py", raw_secret)

    finding1 = ScanFinding(
        rule_id="aws-access-key",
        rule_name="AWS Access Key",
        severity="HIGH",
        file_path="legacy_file.py",
        line_number=10,
        raw_value=raw_secret,
        masked_value="AKIA...MPLE",
        fingerprint=canonical_fp,
    )

    # 1. Matching via canonical fingerprint
    new_f, supp = filter_baseline_findings([finding1], {canonical_fp})
    assert len(new_f) == 0
    assert len(supp) == 1

    # 2. Matching via legacy fingerprint in existing baseline
    new_f, supp = filter_baseline_findings([finding1], {legacy_fp})
    assert len(new_f) == 0
    assert len(supp) == 1


def test_bug2_sarif_includes_occurrences():
    """SARIF report includes all occurrence locations and occurrenceCount."""
    f = ScanFinding(
        rule_id="aws-access-key",
        rule_name="AWS Access Key",
        severity="HIGH",
        file_path="main.py",
        line_number=5,
        raw_value="AKIAIOSFODNN7EXAMPLE",
        masked_value="AKIA...MPLE",
        fingerprint=compute_fingerprint("aws-access-key", "AKIAIOSFODNN7EXAMPLE"),
        occurrences=[
            {"file_path": "other.py", "line_number": 12, "column": 1, "end_column": 20},
        ],
    )
    sarif = generate_sarif([f], tool_version="0.9.9")
    result = sarif["runs"][0]["results"][0]
    assert len(result["locations"]) == 2
    assert result["properties"]["occurrenceCount"] == 2


# ==============================================================================
# Bug #3: Remediation False Positives / Non-Secret Variables
# ==============================================================================


def test_bug3_refuse_non_secret_variables(tmp_path):
    """envguard fix must refuse remediation on non-secret variables like QUEUE_KEY, TEST_KEY, etc."""
    py_file = tmp_path / "constants.py"
    py_file.write_text(
        'QUEUE_KEY = "queue_worker_process_main_channel_prod_v2"\n'
        'TEST_KEY = "test_run_isolation_token_fixture_setup_12345"\n'
        'SEEN_HASHES_KEY = "seen_hashes_bucket_index_cache_v1"\n'
        'BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"\n'
        'REGISTRY_KEY = "registry_service_lookup_entry_point_prod"\n',
        encoding="utf-8",
    )

    # Force simulated findings on these lines
    findings = [
        ScanFinding(
            rule_id="generic-secret",
            rule_name="Generic Secret",
            severity="MEDIUM",
            file_path="constants.py",
            line_number=1,
            raw_value="queue_worker_process_main_channel_prod_v2",
            masked_value="queu...v2",
            fingerprint="fp1",
            line_snippet='QUEUE_KEY = "queue_worker_process_main_channel_prod_v2"',
        ),
        ScanFinding(
            rule_id="generic-secret",
            rule_name="Generic Secret",
            severity="MEDIUM",
            file_path="constants.py",
            line_number=2,
            raw_value="test_run_isolation_token_fixture_setup_12345",
            masked_value="test...345",
            fingerprint="fp2",
            line_snippet='TEST_KEY = "test_run_isolation_token_fixture_setup_12345"',
        ),
        ScanFinding(
            rule_id="generic-high-entropy-secret",
            rule_name="Generic High Entropy Secret",
            severity="HIGH",
            file_path="constants.py",
            line_number=4,
            raw_value="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
            masked_value="1234...wxyz",
            fingerprint="fp4",
            line_snippet='BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"',
        ),
    ]

    plan = create_remediation_plan(target_root=tmp_path, findings=findings)

    # All proposed actions must be unsafe (manual remediation required)
    assert len(plan.safe_actions) == 0
    assert len(plan.manual_actions) == len(findings)

    # Never add to .env or .env.example
    assert len(plan.env_additions) == 0
    assert len(plan.example_additions) == 0

    # Applying plan must not create or modify .env, .env.example, or constants.py
    orig_content = py_file.read_text(encoding="utf-8")
    apply_remediation_plan(plan)
    assert not (tmp_path / ".env").exists()
    assert not (tmp_path / ".env.example").exists()
    assert py_file.read_text(encoding="utf-8") == orig_content


def test_bug3_accept_genuine_secrets(tmp_path):
    """envguard fix must continue to safely remediate genuine secrets."""
    py_file = tmp_path / "app_config.py"
    py_file.write_text(
        'DATABASE_PASSWORD = "production_super_secret_db_pass_999!"\n',
        encoding="utf-8",
    )

    finding = ScanFinding(
        rule_id="db-password-assignment",
        rule_name="Database Password Assignment",
        severity="HIGH",
        file_path="app_config.py",
        line_number=1,
        raw_value="production_super_secret_db_pass_999!",
        masked_value="prod...999!",
        fingerprint="fp_db_pass",
        line_snippet='DATABASE_PASSWORD = "production_super_secret_db_pass_999!"',
    )

    plan = create_remediation_plan(target_root=tmp_path, findings=[finding])

    assert len(plan.safe_actions) == 1
    assert len(plan.manual_actions) == 0
    assert "DATABASE_PASSWORD" in plan.env_additions
    assert plan.env_additions["DATABASE_PASSWORD"] == "production_super_secret_db_pass_999!"
    assert plan.example_additions["DATABASE_PASSWORD"] == "your-secret-key-here"

    # Apply changes
    apply_remediation_plan(plan)
    assert (tmp_path / ".env").exists()
    assert (tmp_path / ".env.example").exists()
    assert 'DATABASE_PASSWORD="production_super_secret_db_pass_999!"' in (tmp_path / ".env").read_text(encoding="utf-8")
    assert 'DATABASE_PASSWORD="your-secret-key-here"' in (tmp_path / ".env.example").read_text(encoding="utf-8")
