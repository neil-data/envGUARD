"""Pattern definitions and loader for EnvGuard secret detection."""

from dataclasses import dataclass
import importlib.resources
import json
from pathlib import Path
import re
from typing import Dict, List, Optional, Set

from envguard.utils import is_placeholder


@dataclass
class Pattern:
    id: str
    name: str
    regex: str
    compiled: re.Pattern
    severity: str  # "HIGH", "MEDIUM", "LOW"
    description: str = ""
    enabled: bool = True

    @property
    def confidence(self) -> str:
        """Backwards compatibility alias for severity."""
        return self.severity

    def find_matches(self, line: str):
        """Find non-placeholder matches in a line of text.

        Yields tuples of (matched_secret, match_start, match_end).
        """
        if not self.enabled:
            return

        for match in self.compiled.finditer(line):
            # If the pattern has capturing groups, use group 1 as the secret value
            if match.groups() and match.group(1):
                secret_val = match.group(1)
            else:
                secret_val = match.group(0)

            # Skip obvious placeholders and empty strings
            if is_placeholder(secret_val):
                continue

            yield secret_val, match.start(), match.end()


def get_builtin_fallback_patterns() -> List[Pattern]:
    """Emergency fallback patterns hardcoded in Python."""
    fallbacks = [
        ("aws-access-key", "AWS Access Key", r"\bAKIA[0-9A-Z]{16}\b", "HIGH", "AWS Access Key ID"),
        ("github-token", "GitHub Personal Access Token", r"\b(?:ghp_[a-zA-Z0-9]{30,40}|github_pat_[a-zA-Z0-9_]{22,})\b", "HIGH", "GitHub Token"),
        ("stripe-secret-key", "Stripe Secret Key", r"\b(?:sk|rk)_(?:live|test)_[a-zA-Z0-9]{24,}\b", "HIGH", "Stripe Secret Key"),
        ("pem-private-key", "Private Key", r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----", "HIGH", "PEM Private Key header"),
        ("api-key-assignment", "API Key Assignment", r"(?i)(?:api_key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?", "MEDIUM", "API key assignment"),
        ("secret-assignment", "Secret Assignment", r"(?i)(?:secret|client_secret)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?", "MEDIUM", "Secret assignment"),
        ("password-assignment", "Password Assignment", r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"#]{8,})['\"]?", "MEDIUM", "Password assignment"),
    ]
    result = []
    for pid, name, reg, sev, desc in fallbacks:
        result.append(
            Pattern(
                id=pid,
                name=name,
                regex=reg,
                compiled=re.compile(reg),
                severity=sev,
                description=desc,
            )
        )
    return result


def parse_patterns_from_dict(
    data: dict,
    disabled_rules: Optional[Set[str]] = None,
    severity_overrides: Optional[Dict[str, str]] = None,
) -> List[Pattern]:
    """Parse list of Pattern objects from a loaded JSON dictionary."""
    patterns = []
    disabled = disabled_rules or set()
    overrides = severity_overrides or {}

    for item in data.get("patterns", []):
        try:
            rule_id = item.get("id") or item.get("name", "unknown").lower().replace(" ", "-")
            name = item.get("name", rule_id)
            pattern_str = item.get("regex")
            # Support both severity and legacy confidence
            severity = overrides.get(rule_id, item.get("severity") or item.get("confidence", "MEDIUM")).upper()
            description = item.get("description", "")
            enabled = rule_id not in disabled

            if not pattern_str:
                continue

            compiled = re.compile(pattern_str)
            patterns.append(
                Pattern(
                    id=rule_id,
                    name=name,
                    regex=pattern_str,
                    compiled=compiled,
                    severity=severity,
                    description=description,
                    enabled=enabled,
                )
            )
        except re.error:
            # Skip invalid regex without crashing
            continue
    return patterns


def load_default_patterns(
    disabled_rules: Optional[Set[str]] = None,
    severity_overrides: Optional[Dict[str, str]] = None,
) -> List[Pattern]:
    """Load default secret patterns packaged in envguard/data/patterns.json."""
    data_content = None

    # Try importlib.resources (Python 3.10+)
    try:
        if hasattr(importlib.resources, "files"):
            data_file = importlib.resources.files("envguard.data").joinpath("patterns.json")
            data_content = data_file.read_text(encoding="utf-8")
        else:
            data_content = importlib.resources.read_text("envguard.data", "patterns.json", encoding="utf-8")
    except Exception:
        pass

    # Fallback to direct path relative to this file
    if not data_content:
        local_path = Path(__file__).parent / "data" / "patterns.json"
        if local_path.is_file():
            data_content = local_path.read_text(encoding="utf-8")

    if not data_content:
        patterns = get_builtin_fallback_patterns()
        disabled = disabled_rules or set()
        overrides = severity_overrides or {}
        for p in patterns:
            if p.id in disabled:
                p.enabled = False
            if p.id in overrides:
                p.severity = overrides[p.id].upper()
        return patterns

    try:
        parsed = json.loads(data_content)
        return parse_patterns_from_dict(
            parsed,
            disabled_rules=disabled_rules,
            severity_overrides=severity_overrides,
        )
    except Exception:
        return get_builtin_fallback_patterns()
