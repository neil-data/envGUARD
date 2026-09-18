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
    "client_secret",
    "app_secret",
    "shared_secret",
    "password",
    "database_password",
    "db_password",
    "db_pass",
    "admin_password",
    "user_password",
    "root_password",
    "passphrase",
    "passwd",
    "pwd",
    "token",
    "access_token",
    "auth_token",
    "refresh_token",
    "session_token",
    "id_token",
    "bearer_token",
    "jwt_token",
    "api_token",
    "security_token",
    "personal_token",
    "private_key",
    "privkey",
    "priv_key",
    "secret_bytes",
    "signing_key",
    "master_key",
    "encryption_key",
    "decryption_key",
    "credential",
    "credentials",
    "user_cred",
    "auth_cred",
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
    "fingerprint",
    "trace_id",
    "request_id",
    "correlation_id",
    "guid",
    "uuid",
    "uses",
    "image",
    "runs-on",
    "file",
    "path",
    "filename",
    "filepath",
    "queue_key",
    "queue",
    "test_key",
    "test_",
    "seen_hashes",
    "registry_key",
    "registry",
    "alphabet",
    "charset",
    "cache_key",
    "cache",
    "routing_key",
    "storage_key",
    "partition_key",
    "sort_key",
    "primary_key",
    "foreign_key",
    "id_key",
    "object_key",
    "type_key",
    "tag_key",
    "public_key",
    "pubkey",
    "pub_key",
    "license_key",
    "mutex_key",
    "lock_key",
    "metric_key",
    "event_key",
    "format",
    "encoding",
    "schema",
    "table",
    "column",
    "algorithm",
    "control",
    "controls",
    "defeat",
    "defeats",
    "sequence",
    "domain",
    "domains",
    "flag",
    "flags",
    "permission",
    "permissions",
    "name",
    "names",
    "package",
    "packages",
    "import",
    "imports",
    "class",
    "component",
    "style",
    "margin",
    "font",
    "padding",
    "display",
    "position",
    "transparent",
    "color",
    "width",
    "height",
    "min_distance",
    "max_distance",
    "damping",
    "damping_factor",
    "opacity",
    "depth_write",
    "wireframe",
    "ra_of_asc_node",
    "arg_of_pericenter",
    "mean_anomaly",
    "mean_motion",
    "tle_age",
    "rev_delta",
    "time_delay",
    "delay",
    "timeout",
    "interval",
    "ratio",
    "offset",
    "scale",
    "threshold",
    "limit",
    "count",
    "length",
    "size",
    "index",
    "rate",
    "speed",
    "velocity",
    "coordinate",
    "latitude",
    "longitude",
    "altitude",
    "globe_ref",
    "canvas_ref",
    "div_ref",
    "element_ref",
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


def _normalize_identifier(identifier: str) -> str:
    """Convert camelCase, PascalCase, and separated identifiers to lower snake_case."""
    s1 = re.sub(r'(.)([A-Z][a-z]+)', r'\1_\2', identifier)
    s2 = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', s1)
    return s2.lower().replace("-", "_").replace(".", "_")


def analyze_context(var_name: str, value: str = "") -> ContextResult:
    """Analyze variable name to identify credential intent or non-secret metadata context."""
    if not var_name:
        return ContextResult()

    normalized = _normalize_identifier(var_name.strip())

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
            score_modifier=-60,
        )

    if is_credential:
        return ContextResult(
            is_credential_context=True,
            is_non_secret_context=False,
            signals=["credential_variable_name"],
            score_modifier=30,
        )

    return ContextResult()


def is_line_credential_context(line: str) -> bool:
    """Check if line contains explicit credential context (authorization headers or auth functions)."""
    clean_line = line.strip()
    if re.search(r"""(?i)(?:Authorization|Proxy-Authorization)\s*:\s*['"]?(?:Bearer|Basic|Token)\b""", clean_line):
        return True
    if re.search(r"""(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9_.-]{20,}""", clean_line):
        return True
    if re.search(r"""(?i)\b(?:verify_custom_token|verify_token|set_password|validate_credential|authenticate)\s*\(""", clean_line):
        return True
    return False
