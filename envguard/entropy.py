"""Shannon entropy and context-aware analysis for EnvGuard secret detection.

Used as a supporting signal to distinguish realistic secrets from low-entropy
placeholders, commit hashes, UUIDs, and dummy strings.
"""

from collections import Counter
import math
import re
from typing import List, Tuple

UUID_REGEX = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
HEX_ONLY_REGEX = re.compile(r"^[0-9a-fA-F]+$")

# Common credential-indicating keyword substrings in variable or key names
CREDENTIAL_KEYWORDS = (
    "secret",
    "token",
    "password",
    "passwd",
    "pwd",
    "api_key",
    "apikey",
    "access_key",
    "auth",
    "private_key",
    "client_secret",
)


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
    return bool(UUID_REGEX.match(value.strip().strip("'\"")))


def is_generic_hash_or_commit(value: str) -> bool:
    """Check if value looks like a standalone git commit hash or checksum."""
    val = value.strip().strip("'\"")
    # Git short hash (7-12) or full SHA-1 (40) or SHA-256 (64)
    if len(val) in (7, 8, 10, 12, 32, 40, 64) and HEX_ONLY_REGEX.match(val):
        # If all lowercase or all uppercase hex, likely a commit or checksum
        return True
    return False


def is_credential_variable(var_name: str) -> bool:
    """Check if a variable name suggests secret or credential storage."""
    clean = var_name.strip().lower()
    return any(keyword in clean for keyword in CREDENTIAL_KEYWORDS)


def analyze_entropy_and_context(
    value: str,
    var_name: str = "",
    min_length: int = 16,
    entropy_threshold: float = 3.2,
) -> Tuple[bool, List[str]]:
    """Analyze secret candidate using Shannon entropy and contextual signals.

    Returns (is_suspicious, detection_signals).
    Never evaluates entropy in isolation without contextual validation.
    """
    val = value.strip().strip("'\"")
    signals: List[str] = []

    if len(val) < min_length:
        return False, signals

    # Discard non-secrets that happen to look random
    if is_uuid(val):
        return False, ["UUID format (excluded)"]

    # Calculate entropy
    entropy = calculate_entropy(val)

    has_cred_name = is_credential_variable(var_name) if var_name else False
    if has_cred_name:
        signals.append(f"credential-like variable name ('{var_name}')")

    if len(val) >= min_length:
        signals.append(f"length threshold passed ({len(val)} chars)")

    if entropy >= entropy_threshold:
        signals.append(f"high entropy value ({entropy:.2f})")

    # If it's a generic hex hash with no credential variable name, don't flag
    if is_generic_hash_or_commit(val) and not has_cred_name:
        return False, ["standalone hex hash / build id (excluded)"]

    # Suspicious when high entropy combined with credential-like context or sufficient length
    is_suspicious = (entropy >= entropy_threshold) and (has_cred_name or len(val) >= 24)
    return is_suspicious, signals
