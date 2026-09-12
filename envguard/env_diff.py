"""Environment variable drift comparison between .env and .env.example."""

from dataclasses import dataclass
from pathlib import Path
import re
from typing import List, Set, Tuple


@dataclass
class EnvDiffResult:
    missing_from_example: List[str]  # Keys in .env but not in .env.example
    extra_in_example: List[str]      # Keys in .env.example but not in .env
    env_keys_count: int
    example_keys_count: int

    @property
    def has_drift(self) -> bool:
        return bool(self.missing_from_example or self.extra_in_example)


ENV_LINE_REGEX = re.compile(r"^\s*(?:export\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*=")


def parse_env_text(content: str) -> Set[str]:
    """Parse environment variable keys from string content.

    Ignores comments (#) and blank lines.
    Supports KEY=val and export KEY=val.
    Extracts keys only, never stores or inspects values.
    """
    keys: Set[str] = set()
    for line in content.splitlines():
        stripped = line.strip()
        # Ignore comments and blank lines
        if not stripped or stripped.startswith("#"):
            continue

        match = ENV_LINE_REGEX.match(stripped)
        if match:
            key = match.group(1)
            keys.add(key)

    return keys


def parse_env_file(filepath: Path) -> Set[str]:
    """Parse environment variable keys from a file."""
    if not filepath.is_file():
        raise FileNotFoundError(f"File not found: {filepath}")
    content = filepath.read_text(encoding="utf-8", errors="replace")
    return parse_env_text(content)


def diff_env_keys(env_keys: Set[str], example_keys: Set[str]) -> EnvDiffResult:
    """Compare two sets of environment variable keys and identify drift."""
    missing_from_example = sorted(list(env_keys - example_keys))
    extra_in_example = sorted(list(example_keys - env_keys))

    return EnvDiffResult(
        missing_from_example=missing_from_example,
        extra_in_example=extra_in_example,
        env_keys_count=len(env_keys),
        example_keys_count=len(example_keys),
    )


def compare_env_files(env_path: Path, example_path: Path) -> EnvDiffResult:
    """Compare .env and .env.example files directly."""
    env_keys = parse_env_file(env_path)
    example_keys = parse_env_file(example_path)
    return diff_env_keys(env_keys, example_keys)
