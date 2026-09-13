"""Unit tests for JWT detection, Base64URL validation, and header verification."""

import base64
import json
from envguard.detectors.jwt_detector import (
    decode_base64url_segment,
    detect_jwt_candidates,
    is_valid_base64url,
    validate_jwt_structure,
)
from envguard.detectors.scoring import AdvancedDetectionConfig


def _make_jwt(header_dict: dict, payload_dict: dict) -> str:
    h = base64.urlsafe_b64encode(json.dumps(header_dict).encode()).decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps(payload_dict).encode()).decode().rstrip("=")
    sig = base64.urlsafe_b64encode(b"fakesignature1234567890123456").decode().rstrip("=")
    return f"{h}.{p}.{sig}"


def test_valid_jwt_structure_detection():
    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1234567890", "name": "Alice"})
    is_valid, signals = validate_jwt_structure(token)
    assert is_valid
    assert "valid_jwt_header" in signals
    assert "valid_base64url_segments" in signals


def test_invalid_jwt_bad_header():
    # Header is not JSON
    h = base64.urlsafe_b64encode(b"not a json object").decode().rstrip("=")
    p = base64.urlsafe_b64encode(b"{}").decode().rstrip("=")
    token = f"{h}.{p}.sig123"
    is_valid, _ = validate_jwt_structure(token)
    assert not is_valid


def test_invalid_jwt_two_segments():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    is_valid, _ = validate_jwt_structure(token)
    assert not is_valid


def test_jwt_context_aware_severity():
    cfg = AdvancedDetectionConfig(jwt_enabled=True)
    token = _make_jwt({"alg": "RS256"}, {"sub": "user1"})

    # In credential variable context -> HIGH
    cands = detect_jwt_candidates(
        line=f"api_key = '{token}'",
        line_number=1,
        file_path="config.py",
        config=cfg,
    )
    assert len(cands) == 1
    assert cands[0].original_severity == "HIGH"
    assert "credential_variable_name" in cands[0].signals

    # Standalone -> MEDIUM
    cands_standalone = detect_jwt_candidates(
        line=f"token = '{token}'",
        line_number=1,
        file_path="app.py",
        config=cfg,
    )
    assert len(cands_standalone) == 1
    # 'token' is credential variable keyword so it gets HIGH
    assert cands_standalone[0].original_severity == "HIGH"

    # Non-secret context -> LOW
    cands_non_sec = detect_jwt_candidates(
        line=f"session_id = '{token}'",
        line_number=1,
        file_path="cache.py",
        config=cfg,
    )
    assert len(cands_non_sec) == 1
    assert cands_non_sec[0].original_severity == "LOW"


def test_base64url_decoding():
    assert decode_base64url_segment("eyJhbGciOiJIUzI1NiJ9") is not None
    assert decode_base64url_segment("invalid%character") is None
