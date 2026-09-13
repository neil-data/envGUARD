"""Unit tests for the scoring and classification engine."""

from envguard.detectors.scoring import (
    AdvancedDetectionConfig,
    DetectionCandidate,
    SEVERITY_ORDER,
    classify_severity,
    score_candidate,
)


def test_score_candidate_signal_weights():
    cand = DetectionCandidate(
        value="test_candidate_val",
        var_name="api_key",
        line="api_key = 'test_candidate_val'",
        line_number=1,
        file_path="test.py",
        source="entropy",
        signals=["high_entropy", "credential_variable_name", "token_like_length"],
        original_severity=None,
    )
    res = score_candidate(cand)
    # Weights: high_entropy (30) + credential_variable_name (25) + token_like_length (20) = 75
    assert res.total_score == 75
    assert res.severity == "MEDIUM"
    assert "high_entropy" in res.signals


def test_score_candidate_preserves_original_severity():
    cand = DetectionCandidate(
        value="AKIA1234567890ABCDEF",
        var_name="",
        line="AKIA1234567890ABCDEF",
        line_number=1,
        file_path="test.py",
        source="regex",
        signals=["known_pattern_match"],
        rule_id="aws-access-key",
        original_severity="HIGH",
    )
    res = score_candidate(cand)
    assert res.severity == "HIGH"


def test_classify_severity_thresholds():
    assert classify_severity(85) == "HIGH"
    assert classify_severity(80) == "HIGH"
    assert classify_severity(65) == "MEDIUM"
    assert classify_severity(50) == "MEDIUM"
    assert classify_severity(30) == "LOW"
    assert classify_severity(20) == "LOW"
    assert classify_severity(15) == "IGNORE"
    assert classify_severity(0) == "IGNORE"


def test_severity_order_monotonicity():
    assert SEVERITY_ORDER["HIGH"] > SEVERITY_ORDER["MEDIUM"]
    assert SEVERITY_ORDER["MEDIUM"] > SEVERITY_ORDER["LOW"]
    assert SEVERITY_ORDER["LOW"] > SEVERITY_ORDER["IGNORE"]
