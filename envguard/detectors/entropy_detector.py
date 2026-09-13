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


def is_code_expression(value: str) -> bool:
    """Check if value is a code expression (e.g. function call, environment lookup) rather than a literal secret."""
    clean = value.strip()
    if not clean:
        return False
    # Type hints / generic subscripts: e.g. Optional[...], List[...]
    if ("[" in clean and "]" in clean) or re.search(r"^(?:Optional|List|Dict|Tuple|Set|Union)\[", clean):
        return True
    # Attribute access / dotted identifier: e.g. config.disabled_rules, self.foo, a.b.c
    if re.search(r"^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_]", clean):
        return True
    # Check for known modules, functions, or runtime calls
    code_indicators = (
        "os.environ",
        "os.getenv",
        "environ.get",
        "process.env",
        "sys.",
        "re.compile",
        "config.get",
        "settings.get",
        "System.getenv",
        "getattr(",
        "lambda ",
        "${",
    )
    if any(ind in clean for ind in code_indicators):
        return True
    # Identifier immediately followed by '(' indicating a function or method invocation
    if re.search(r"[A-Za-z_][A-Za-z0-9_]*\s*\(", clean):
        return True
    # Unmatched trailing parenthesis or bracket from split expression
    if clean.endswith(")") or clean.endswith("]"):
        return True
    return False


def is_env_or_code_context(val: str, line: str) -> bool:
    """Check if a string literal appears inside an environment lookup or re.compile call."""
    if not line:
        return False
    escaped = re.escape(val)
    patterns = (
        r"""(?:os\.environ(?:\.get)?|os\.getenv|environ\.get|System\.getenv|process\.env)\s*[\(\[]\s*['"]""" + escaped + r"""['"]""",
        r"""re\.compile\s*\(\s*(?:r)?['"]""" + escaped + r"""['"]""",
        r"""(?:config|settings|request|params|args)\.get\s*\(\s*['"]""" + escaped + r"""['"]""",
    )
    for pat in patterns:
        if re.search(pat, line):
            return True
    return False


def is_regex_literal(value: str, line: str = "") -> bool:
    """Check if value represents a regular expression pattern rather than a credential."""
    clean = value.strip().strip("'\"")
    if not clean:
        return False

    # Check if prefixed with r' or r" in line
    if line:
        escaped = re.escape(value)
        if re.search(r"""r['"]""" + escaped + r"""['"]""", line):
            return True

    # Characteristic regex constructs and character classes
    regex_indicators = (
        r"[a-zA-Z",
        r"[0-9",
        r"[A-Z",
        r"[a-z",
        r"[A-Za-z",
        r"\d",
        r"\w",
        r"\s",
        r"\b",
        r"(?:",
        r"(?i)",
        r"(?m)",
        r"(?P<",
        r"(?=",
        r"(?!",
        r"(?<= ",
        r"(?<!",
        r"^[",
        r"]$",
    )
    if any(ind in clean for ind in regex_indicators):
        return True

    # Anchored patterns with regex meta characters
    if (clean.startswith("^") or clean.endswith("$")) and any(c in clean for c in "*+?{}[]()|\\"):
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


def extract_literal_candidates(line: str) -> List[Tuple[str, str]]:
    """Extract assignment pairs and standalone quoted string literals from a line."""
    candidates: List[Tuple[str, str]] = []
    seen_values = set()

    # 1. Assignment pairs (var_name, val)
    for var_name, val in extract_assignment_candidates(line):
        clean_val = val.strip().strip("'\"")
        if clean_val and clean_val not in seen_values:
            candidates.append((var_name, clean_val))
            seen_values.add(clean_val)

    # 2. Standalone quoted string literals
    for match in re.finditer(r"""(?<![a-zA-Z0-9_])(['"])(.*?)\1""", line):
        clean_val = match.group(2).strip()
        if clean_val and clean_val not in seen_values:
            candidates.append(("", clean_val))
            seen_values.add(clean_val)

    return candidates


def detect_entropy_candidates(
    line: str,
    line_number: int,
    file_path: str,
    config: AdvancedDetectionConfig,
) -> List[DetectionCandidate]:
    """Scan a line for high-entropy secret candidates, running independently when regex rules miss."""
    if not config.entropy_enabled:
        return []

    candidates: List[DetectionCandidate] = []
    extracted = extract_literal_candidates(line)

    for var_name, val in extracted:
        # 1. Length check
        if len(val) < config.entropy_min_length:
            continue

        # 2. Secrets are discrete tokens; skip multi-word strings containing whitespace
        if any(c.isspace() for c in val):
            continue

        # 3. Skip URLs, schema references, file paths, and action/image references
        if val.startswith("http://") or val.startswith("https://") or "://" in val or val.startswith("/") or val.startswith("./"):
            continue
        if ("/" in val and ("@" in val or ":" in val)) or re.search(r"\.(?:md|yml|yaml|json|toml|txt|html|py|js|ts|css|sh|xml|csv|tar\.gz|zip)$", val, re.IGNORECASE):
            continue

        # 4. Skip format strings or template expressions
        if "{" in val or "}" in val or "%" in val:
            continue

        # 5. Skip placeholders immediately
        if is_placeholder(val):
            continue


        # 3. Skip code expressions (e.g. os.environ.get, os.getenv, method calls)
        if is_code_expression(val) or is_env_or_code_context(val, line):
            continue

        # 4. Skip regex literals
        if is_regex_literal(val, line):
            continue

        # 5. Skip UUIDs
        if is_uuid(val):
            continue

        # 6. Context check
        context_res = analyze_context(var_name, val) if var_name else None

        # 7. Skip generic hex hashes unless explicitly in credential context
        if is_generic_hash_or_commit(val) and not (context_res and context_res.is_credential_context):
            continue

        if HEX_ONLY_REGEX.match(val) and not (context_res and context_res.is_credential_context):
            continue

        # 8. Skip non-secret context (e.g. session_id, commit, checksum, version)
        if context_res and context_res.is_non_secret_context:
            continue

        # 9. Shannon entropy check
        entropy = calculate_entropy(val)
        if entropy < config.entropy_threshold:
            continue

        signals: List[str] = ["high_entropy", "token_like_length", "non_placeholder_value"]

        # 10. Apply context signals if available
        if context_res and context_res.signals:
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
            original_severity="MEDIUM",
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
