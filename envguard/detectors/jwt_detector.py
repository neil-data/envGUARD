"""JWT detection with structural validation, Base64URL decoding, and header verification."""

import base64
import json
import re
from typing import List, Optional, Tuple

from envguard.detectors.context_detector import analyze_context
from envguard.detectors.entropy_detector import extract_assignment_candidates
from envguard.detectors.scoring import AdvancedDetectionConfig, DetectionCandidate
from envguard.utils import mask_secret

JWT_REGEX = re.compile(r"\b(ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b")
BASE64URL_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
VALID_JWT_HEADER_FIELDS = {"alg", "typ", "kid", "jku", "x5u"}


def is_valid_base64url(s: str) -> bool:
    """Check if all characters in the string belong to Base64URL character set."""
    return bool(s) and all(c in BASE64URL_CHARS for c in s)


def decode_base64url_segment(segment: str) -> Optional[bytes]:
    """Safely decode a Base64URL string adding required padding."""
    if not is_valid_base64url(segment):
        return None
    rem = len(segment) % 4
    padded = segment + ("=" * (4 - rem) if rem else "")
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception:
        return None


def validate_jwt_structure(token: str) -> Tuple[bool, List[str]]:
    """Validate that token matches JWT specification and header is valid JSON."""
    parts = token.split(".")
    if len(parts) != 3:
        return False, []

    header_seg, payload_seg, signature_seg = parts
    if not (is_valid_base64url(header_seg) and is_valid_base64url(payload_seg) and is_valid_base64url(signature_seg)):
        return False, []

    header_bytes = decode_base64url_segment(header_seg)
    if not header_bytes:
        return False, []

    try:
        header_json = json.loads(header_bytes.decode("utf-8"))
        if not isinstance(header_json, dict):
            return False, []
    except Exception:
        return False, []

    # Check for presence of standard JWT header keys
    has_jwt_header_field = any(k in header_json for k in VALID_JWT_HEADER_FIELDS)
    if not has_jwt_header_field:
        return False, []

    signals = ["jwt_structure", "valid_base64url_segments", "valid_jwt_header"]
    return True, signals


def detect_jwt_candidates(
    line: str,
    line_number: int,
    file_path: str,
    config: AdvancedDetectionConfig,
) -> List[DetectionCandidate]:
    """Scan line for valid JWT tokens."""
    if not config.jwt_enabled:
        return []

    candidates: List[DetectionCandidate] = []
    # Find any variable name associated with the line
    var_name = ""
    assignments = extract_assignment_candidates(line)
    if assignments:
        var_name = assignments[0][0]

    for match in JWT_REGEX.finditer(line):
        token = match.group(1).strip()
        is_valid, signals = validate_jwt_structure(token)
        if not is_valid:
            continue

        signals.append("valid_jwt")

        context_res = analyze_context(var_name, token)
        if context_res.is_credential_context:
            signals.append("credential_variable_name")
            initial_severity = "HIGH"
        elif context_res.is_non_secret_context:
            signals.append("non_secret_context")
            initial_severity = "LOW"
        else:
            # Standalone JWT without explicit credential context
            initial_severity = "MEDIUM"

        from envguard.scanner import compute_fingerprint
        fp = compute_fingerprint("jwt-token", file_path, token)
        masked = mask_secret(token)

        candidate = DetectionCandidate(
            value=token,
            var_name=var_name,
            line=line,
            line_number=line_number,
            file_path=file_path,
            source="jwt",
            signals=signals,
            rule_id="jwt-token",
            rule_name="JSON Web Token (JWT)",
            original_severity=initial_severity,
            fingerprint=fp,
            masked_value=masked,
        )
        candidates.append(candidate)

    return candidates
