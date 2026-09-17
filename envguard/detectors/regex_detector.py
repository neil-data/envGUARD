"""Regex pattern detector integrating existing and expanded pattern rules."""

import re
from typing import List, Optional

from envguard.detectors.entropy_detector import (
    extract_assignment_candidates,
    is_code_expression,
    is_env_or_code_context,
)
from envguard.detectors.scoring import DetectionCandidate
from envguard.patterns import Pattern
from envguard.secrets_manager import detect_secrets_manager_reference
from envguard.utils import mask_secret

PROVIDER_PREFIX_RULES = {
    "aws-access-key": "AWS",
    "aws-secret-access-key": "AWS",
    "aws-session-token": "AWS",
    "google-api-key": "Google",
    "google-service-account-key": "Google",
    "azure-storage-connection-string": "Azure",
    "azure-storage-key": "Azure",
    "github-token": "GitHub",
    "gitlab-token": "GitLab",
    "npm-token": "npm",
    "pypi-token": "PyPI",
    "stripe-secret-key": "Stripe",
    "slack-token": "Slack",
    "discord-token": "Discord",
}


def detect_regex_candidates(
    line: str,
    line_number: int,
    file_path: str,
    patterns: List[Pattern],
    full_text: Optional[str] = None,
) -> List[DetectionCandidate]:
    """Match line against compiled regex patterns and generate scored candidates."""
    candidates: List[DetectionCandidate] = []
    assignments = extract_assignment_candidates(line)
    var_name = assignments[0][0] if assignments else ""

    for pattern in patterns:
        if not pattern.enabled:
            continue
        # generic-high-entropy-secret is an algorithmic entropy rule evaluated by the entropy detector
        if pattern.id == "generic-high-entropy-secret":
            continue


        is_assignment_pattern = pattern.id.endswith("-assignment") or pattern.id in {
            "generic-credential",
            "generic-secret",
        }

        # If line contains a secrets manager or environment lookup, assignment rules should not flag it
        if is_assignment_pattern and detect_secrets_manager_reference(line):
            continue

        for secret_val, start, end in pattern.find_matches(line):
            if is_env_or_code_context(secret_val, line):
                continue

            if is_assignment_pattern:
                # Check if secret_val is code, function call, or environment lookup
                if is_code_expression(secret_val):
                    continue

                # If matched value is immediately followed by '(', it is a function invocation (e.g. func())
                if re.match(r"^\s*\(", line[end:]):
                    continue

                # If matched value is immediately preceded by '.', it is an attribute access (e.g. obj.val)
                if line[:start].rstrip().endswith("."):
                    continue

                rhs = line[start:].strip()
                if is_code_expression(rhs):
                    continue

            # Special validation for Google Service Account Key:
            # Require multiple service account fields (e.g. private_key or client_email) to avoid false positives
            if pattern.id == "google-service-account-key":
                search_scope = full_text if full_text is not None else line
                has_private_key = "private_key" in search_scope
                has_client_email = "client_email" in search_scope
                has_project_id = "project_id" in search_scope
                if not (has_private_key or has_client_email or has_project_id):
                    continue

            signals = ["known_pattern_match"]

            if "private-key" in pattern.id or "private_key" in pattern.id:
                signals.append("private_key_header")

            provider = PROVIDER_PREFIX_RULES.get(pattern.id)
            if provider:
                signals.append("provider_prefix")

            from envguard.scanner import compute_fingerprint
            fp = compute_fingerprint(pattern.id, file_path, secret_val)
            masked = mask_secret(secret_val)

            candidate = DetectionCandidate(
                value=secret_val,
                var_name=var_name,
                line=line,
                line_number=line_number,
                file_path=file_path,
                source="regex",
                signals=signals,
                rule_id=pattern.id,
                rule_name=pattern.name,
                original_severity=pattern.severity,
                provider=provider,
                fingerprint=fp,
                masked_value=masked,
            )
            candidates.append(candidate)

    return candidates
