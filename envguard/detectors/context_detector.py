"""Context analysis for variable names and surrounding assignment structures."""

from dataclasses import dataclass, field
import re
from typing import List

CREDENTIAL_KEYWORDS = (
    "api_key",
    "apikey",
    "secret",
    "secret_key",
    "secretkey",
    "password",
    "database_password",
    "db_password",
    "db_pass",
    "token",
    "access_token",
    "auth_token",
    "private_key",
    "client_secret",
    "encryption_key",
    "credential",
)

NON_SECRET_KEYWORDS = (
    "session_id",
    "build_hash",
    "version",
    "checksum",
    "commit",
    "revision",
    "hash",
    "digest",
    "trace_id",
    "request_id",
    "correlation_id",
)

ASSIGNMENT_REGEX = re.compile(
    r"""(?:^|[\s,;])(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[:=]\s*(?:(['"])(.*?)\2|([^\s;#,'"]\S*))""",
    re.IGNORECASE,
)


@dataclass
class ContextResult:
    """Result of context heuristic inspection."""
    is_credential_context: bool = False
    is_non_secret_context: bool = False
    signals: List[str] = field(default_factory=list)
    score_modifier: int = 0


def analyze_context(var_name: str, value: str = "") -> ContextResult:
    """Analyze variable name to identify credential intent or non-secret metadata context."""
    if not var_name:
        return ContextResult()

    clean = var_name.strip().lower()
    # Normalize separators
    normalized = clean.replace("-", "_").replace(".", "_")

    # Check non-secret context first
    is_non_secret = any(kw in normalized for kw in NON_SECRET_KEYWORDS)
    # Check credential context
    is_credential = any(kw in normalized for kw in CREDENTIAL_KEYWORDS)

    # Non-secret context takes priority when conflicting (e.g., session_id should not flag as credential)
    if is_non_secret and not is_credential:
        return ContextResult(
            is_credential_context=False,
            is_non_secret_context=True,
            signals=["non_secret_context"],
            score_modifier=-50,
        )

    if is_credential:
        return ContextResult(
            is_credential_context=True,
            is_non_secret_context=False,
            signals=["credential_variable_name"],
            score_modifier=25,
        )

    return ContextResult()
