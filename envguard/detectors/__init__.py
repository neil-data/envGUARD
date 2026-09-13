"""Advanced detection engine for EnvGuard v0.4.0.

Provides multi-signal secret detection combining:
- Shannon entropy analysis
- JWT structure validation
- Context-aware variable analysis
- Multi-signal scoring

All detection runs 100% locally with no network calls.
"""

from envguard.detectors.context_detector import ContextResult, analyze_context
from envguard.detectors.entropy_detector import (
    calculate_entropy,
    detect_entropy_candidates,
    is_credential_variable,
    is_generic_hash_or_commit,
    is_uuid,
)
from envguard.detectors.jwt_detector import detect_jwt_candidates, validate_jwt_structure
from envguard.detectors.regex_detector import detect_regex_candidates
from envguard.detectors.scoring import (
    AdvancedDetectionConfig,
    DetectionCandidate,
    ScoredResult,
    classify_severity,
    score_candidate,
)

__all__ = [
    "AdvancedDetectionConfig",
    "DetectionCandidate",
    "ScoredResult",
    "ContextResult",
    "score_candidate",
    "classify_severity",
    "calculate_entropy",
    "is_uuid",
    "is_generic_hash_or_commit",
    "is_credential_variable",
    "detect_entropy_candidates",
    "detect_jwt_candidates",
    "detect_regex_candidates",
    "analyze_context",
    "validate_jwt_structure",
]
