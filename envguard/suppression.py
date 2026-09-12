"""Inline finding suppression manager for EnvGuard.

Supported comment patterns: (Philosophy: handles # // /* */)
- envguard: ignore
- envguard: ignore=RULE_ID
- envguard: ignore-next-line
- envguard: ignore-next-line=RULE_ID
"""

from dataclasses import dataclass, field
import re
from typing import Dict, List, Optional, Set

# Matches "envguard: ignore" or "envguard: ignore=rule-id"
SAME_LINE_PATTERN = re.compile(
    r"envguard[:\s]+\s*ignore(?:\s*=\s*([a-zA-Z0-9_-]+))?",
    re.IGNORECASE,
)

# Matches "envguard: ignore-next-line" or "envguard: ignore-next-line=rule-id"
NEXT_LINE_PATTERN = re.compile(
    r"envguard[:\s]+\s*ignore-next-line(?:\s*=\s*([a-zA-Z0-9_-]+))?",
    re.IGNORECASE,
)


@dataclass
class SuppressionManager:
    """Manages inline suppression directives in a single file."""

    # line_number -> set of rule_ids (use "*" for ignore all)
    line_suppressions: Dict[int, Set[str]] = field(default_factory=dict)

    def add_suppression(self, line_no: int, rule_id: Optional[str] = None):
        """Add a suppression for a specific line number."""
        rule = rule_id.strip().lower() if rule_id else "*"
        if line_no not in self.line_suppressions:
            self.line_suppressions[line_no] = set()
        self.line_suppressions[line_no].add(rule)

    def is_suppressed(self, line_no: int, rule_id: str) -> bool:
        """Check if finding on line_no for rule_id is suppressed."""
        rules = self.line_suppressions.get(line_no)
        if not rules:
            return False
        if "*" in rules:
            return True
        return rule_id.strip().lower() in rules


def parse_suppressions_from_lines(lines: List[str]) -> SuppressionManager:
    """Parse inline suppressions from a list of file lines."""
    mgr = SuppressionManager()
    for line_idx, line in enumerate(lines, start=1):
        # Check for ignore-next-line first
        next_match = NEXT_LINE_PATTERN.search(line)
        if next_match:
            rule = next_match.group(1)
            mgr.add_suppression(line_idx + 1, rule)
            continue

        # Check for same-line ignore
        same_match = SAME_LINE_PATTERN.search(line)
        if same_match:
            rule = same_match.group(1)
            mgr.add_suppression(line_idx, rule)

    return mgr

def parse_suppressions_from_text(text: str) -> SuppressionManager:
    """Parse inline suppressions from a full text string."""
    return parse_suppressions_from_lines(text.splitlines())
