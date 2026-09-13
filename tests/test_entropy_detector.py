"""Unit tests for Shannon entropy detector, assignment parsing, and false-positive filtering."""

from envguard.detectors.entropy_detector import (
    calculate_entropy,
    detect_entropy_candidates,
    extract_assignment_candidates,
    is_credential_variable,
    is_generic_hash_or_commit,
    is_uuid,
)
from envguard.detectors.scoring import AdvancedDetectionConfig


def test_calculate_entropy_basics():
    # Identical chars -> 0.0
    assert calculate_entropy("AAAAAA") == 0.0
    # Alternating -> 1.0
    assert calculate_entropy("ABABABAB") == 1.0
    # High randomness
    ent = calculate_entropy("xK9#mQ2!pZ1@4vL8")
    assert ent >= 3.5


def test_is_uuid():
    assert is_uuid("123e4567-e89b-12d3-a456-426614174000")
    assert is_uuid("c9a646d3-9c61-4cb7-bf7d-b2f619de61bf")
    assert not is_uuid("not-a-valid-uuid-string")
    assert not is_uuid("AKIAIOSFODNN7EXAMPLE")


def test_is_generic_hash_or_commit():
    # 40-char git commit SHA
    assert is_generic_hash_or_commit("da39a3ee5e6b4b0d3255bfef95601890afd80709")
    # 32-char md5
    assert is_generic_hash_or_commit("098f6bcd4621d373cade4e832627b4f6")
    # 64-char sha256
    assert is_generic_hash_or_commit("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    # Not a hex string
    assert not is_generic_hash_or_commit("this_is_not_hex_0123456789abcdefgh")


def test_extract_assignment_candidates():
    pairs = extract_assignment_candidates("export API_KEY = 'supersecretstring123'")
    assert len(pairs) == 1
    assert pairs[0][0] == "API_KEY"
    assert pairs[0][1] == "supersecretstring123"

    pairs_yaml = extract_assignment_candidates("database_password: supersecretstring123")
    assert len(pairs_yaml) == 1
    assert pairs_yaml[0][0] == "database_password"
    assert pairs_yaml[0][1] == "supersecretstring123"


def test_entropy_detector_ignores_low_entropy_and_hashes():
    cfg = AdvancedDetectionConfig(entropy_enabled=True, entropy_threshold=3.5, entropy_min_length=16)

    # Low entropy repeat chars
    cands = detect_entropy_candidates("api_key = 'aaaaaaaaaaaaaaaa'", 1, "test.py", cfg)
    assert len(cands) == 0

    # Git commit hash
    cands_hash = detect_entropy_candidates("commit_hash = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'", 1, "test.py", cfg)
    assert len(cands_hash) == 0

    # Real high-entropy string in credential variable (length >= 16)
    cands_real = detect_entropy_candidates("secret_token = '9Kx#2mP!vQ1@zY7&w8'", 1, "test.py", cfg)
    assert len(cands_real) == 1
    assert "high_entropy" in cands_real[0].signals
