"""Multi-signal scoring engine and candidate data models for EnvGuard v0.4.0."""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class AdvancedDetectionConfig:
    """Configuration options for advanced multi-signal detection."""
    entropy_enabled: bool = True
    entropy_min_length: int = 20
    entropy_threshold: float = 4.0
    jwt_enabled: bool = True
    context_enabled: bool = True


@dataclass
class DetectionCandidate:
    """Candidate secret value and context extracted by detectors."""
    value: str
    var_name: str
    line: str
    line_number: int
    file_path: str
    source: str  # "regex", "entropy", "jwt", "context"
    signals: List[str] = field(default_factory=list)
    base_score: int = 0
    entropy_value: Optional[float] = None
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    provider: Optional[str] = None
    original_severity: Optional[str] = None  # Preserves known regex severity
    fingerprint: Optional[str] = None
    masked_value: Optional[str] = None


@dataclass
class ScoredResult:
    """Scoring output and final severity classification for a candidate."""
    candidate: DetectionCandidate
    total_score: int
    severity: str  # "HIGH", "MEDIUM", "LOW", "IGNORE"
    signals: List[str]
    entropy: Optional[float]
    provider: Optional[str]


# Signal weights for multi-signal scoring
SIGNAL_WEIGHTS = {
    "known_pattern_match": 100,
    "private_key_header": 100,
    "valid_jwt": 80,
    "high_entropy": 30,
    "credential_variable_name": 25,
    "token_like_length": 20,
    "provider_prefix": 15,
    "non_placeholder_value": 10,
    "placeholder_value": -100,
    "uuid_hash_exclusion": -200,
    "non_secret_context": -50,
}

SEVERITY_ORDER = {"IGNORE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
REVERSE_SEVERITY_ORDER = {0: "IGNORE", 1: "LOW", 2: "MEDIUM", 3: "HIGH"}


def classify_severity(score: int) -> str:
    """Map numerical score to severity level."""
    if score >= 80:
        return "HIGH"
    elif score >= 50:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    return "IGNORE"


def score_candidate(candidate: DetectionCandidate) -> ScoredResult:
    """Calculate multi-signal confidence score and determine severity.

    Hard rule: Known regex patterns preserve their original configured severity,
    and are never downgraded by the scoring engine.
    """
    total = candidate.base_score
    active_signals = list(candidate.signals)

    for signal in active_signals:
        total += SIGNAL_WEIGHTS.get(signal, 0)

    computed_severity = classify_severity(total)

    # Enforce preservation of known pattern severity:
    # Known regex patterns must strictly retain their original configured severity.
    final_severity = computed_severity
    if candidate.original_severity:
        final_severity = candidate.original_severity.upper()
    elif candidate.rule_id == "generic-high-entropy-secret":
        final_severity = "MEDIUM"

    return ScoredResult(
        candidate=candidate,
        total_score=total,
        severity=final_severity,
        signals=active_signals,
        entropy=candidate.entropy_value,
        provider=candidate.provider,
    )
