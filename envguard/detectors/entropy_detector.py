"""Shannon entropy detector with context validation and false-positive filtering."""

from collections import Counter
import math
import re
from typing import List, Optional, Tuple

from envguard.detectors.context_detector import (
    ASSIGNMENT_REGEX,
    CREDENTIAL_KEYWORDS,
    analyze_context,
)
from envguard.detectors.scoring import AdvancedDetectionConfig, DetectionCandidate
from envguard.utils import is_placeholder, mask_secret

UUID_REGEX = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
HEX_ONLY_REGEX = re.compile(r"^[0-9a-fA-F]+$")


def calculate_entropy(text: str) -> float:
    """Calculate the Shannon entropy of a string in bits per character.

    Returns 0.0 for empty or single-character strings.
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def is_uuid(value: str) -> bool:
    """Check if value matches standard UUID format (v1-v5)."""
    clean = value.strip().strip("'\"")
    return bool(UUID_REGEX.match(clean))


def is_generic_hash_or_commit(value: str) -> bool:
    """Check if value looks like a standalone git commit hash, checksum, or common hex digest."""
    val = value.strip().strip("'\"")
    # Git short hashes (7-12) or MD5 (32), SHA-1 (40), SHA-256 (64), SHA-512 (128)
    if len(val) in (7, 8, 10, 12, 32, 40, 64, 128) and HEX_ONLY_REGEX.match(val):
        return True
    return False


def is_credential_variable(var_name: str) -> bool:
    """Check if a variable name suggests secret or credential storage."""
    clean = var_name.strip().lower()
    return any(keyword in clean for keyword in CREDENTIAL_KEYWORDS)


def extract_assignment_candidates(line: str) -> List[Tuple[str, str]]:
    """Extract variable name and assigned value pairs from a code or config line."""
    candidates: List[Tuple[str, str]] = []
    for match in ASSIGNMENT_REGEX.finditer(line):
        var_name = match.group(1).strip()
        val = (match.group(3) if match.group(3) is not None else match.group(4) or "").strip().strip("'\"")
        if val:
            candidates.append((var_name, val))
    return candidates


def detect_entropy_candidates(
    line: str,
    line_number: int,
    file_path: str,
    config: AdvancedDetectionConfig,
) -> List[DetectionCandidate]:
    """Scan an assignment-like line for high-entropy secret candidates."""
    if not config.entropy_enabled:
        return []

    candidates: List[DetectionCandidate] = []
    extracted = extract_assignment_candidates(line)

    for var_name, val in extracted:
        # 1. Skip placeholders immediately
        if is_placeholder(val):
            continue

        # 2. Skip UUIDs
        if is_uuid(val):
            continue

        # 3. Skip generic hex hashes unless explicitly in credential context
        context_res = analyze_context(var_name, val)
        if is_generic_hash_or_commit(val) and not context_res.is_credential_context:
            continue

        # 4. Context check: high entropy is only an alert in credential variable contexts
        # (standalone random strings in code like docstrings, dict keys, or generic variables should not be flagged as secrets)
        if not context_res.is_credential_context and not is_credential_variable(var_name):
            continue

        # 5. Length check
        if len(val) < config.entropy_min_length:
            continue

        # 5. Shannon entropy check
        entropy = calculate_entropy(val)
        if entropy < config.entropy_threshold:
            continue

        signals: List[str] = ["high_entropy", "token_like_length", "non_placeholder_value"]

        # 6. Apply context signals
        if context_res.signals:
            signals.extend(context_res.signals)

        # Immediate masking and fingerprinting
        from envguard.scanner import compute_fingerprint
        fp = compute_fingerprint("generic-high-entropy-secret", file_path, val)
        masked = mask_secret(val)

        candidate = DetectionCandidate(
            value=val,
            var_name=var_name,
            line=line,
            line_number=line_number,
            file_path=file_path,
            source="entropy",
            signals=signals,
            entropy_value=entropy,
            rule_id="generic-high-entropy-secret",
            rule_name="High Entropy Secret",
            fingerprint=fp,
            masked_value=masked,
        )
        candidates.append(candidate)

    return candidates


def analyze_entropy_and_context(
    value: str,
    var_name: str = "",
    min_length: int = 16,
    entropy_threshold: float = 3.2,
) -> Tuple[bool, List[str]]:
    """Legacy backward-compatible analysis method."""
    val = value.strip().strip("'\"")
    signals: List[str] = []

    if len(val) < min_length:
        return False, signals

    if is_uuid(val):
        return False, ["UUID format (excluded)"]

    entropy = calculate_entropy(val)
    has_cred_name = is_credential_variable(var_name) if var_name else False
    if has_cred_name:
        signals.append(f"credential-like variable name ('{var_name}')")

    if len(val) >= min_length:
        signals.append(f"length threshold passed ({len(val)} chars)")

    if entropy >= entropy_threshold:
        signals.append(f"high entropy value ({entropy:.2f})")

    if is_generic_hash_or_commit(val) and not has_cred_name:
        return False, ["standalone hex hash / build id (excluded)"]

    is_suspicious = (entropy >= entropy_threshold) and (has_cred_name or len(val) >= 24)
    return is_suspicious, signals
