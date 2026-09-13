"""Legacy compatibility module.

Use envguard.detectors.entropy_detector internally.
"""

from envguard.detectors.entropy_detector import (
    analyze_entropy_and_context,
    calculate_entropy,
    is_credential_variable,
    is_generic_hash_or_commit,
    is_uuid,
)

__all__ = [
    "calculate_entropy",
    "is_uuid",
    "is_generic_hash_or_commit",
    "is_credential_variable",
    "analyze_entropy_and_context",
]
