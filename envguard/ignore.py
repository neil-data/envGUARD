"""Path and file ignore handling for EnvGuard.

Supports:
1. Built-in hardcoded ignores (.git, node_modules, virtualenvs, build artifacts)
2. .gitignore
3. .envguardignore
4. Repository configuration file (.envguard.yml excludes)
"""

from pathlib import Path
from typing import List, Optional, Tuple
import pathspec

ENVGUARDIGNORE_FILENAME = ".envguardignore"

BUILTIN_IGNORED_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".idea",
    ".vscode",
    "venv",
    ".venv",
    "dist",
    "build",
    "egg-info",
    ".envguard_cache",
}

BUILTIN_IGNORED_FILES = {
    ".envguard-baseline.json",
    ".envguard.yml",
    ".envguard.yaml",
    ".envguard-org.yml",
    ".envguard-org.yaml",
    ".envguardignore",
}


def load_envguardignore(base_dir: Path) -> Optional[pathspec.PathSpec]:
    """Load .envguardignore from repository root if it exists."""
    ignore_file = base_dir / ENVGUARDIGNORE_FILENAME
    if ignore_file.is_file():
        try:
            lines = ignore_file.read_text(encoding="utf-8", errors="replace").splitlines()
            return pathspec.PathSpec.from_lines("gitignore", lines)
        except Exception:
            return None
    return None


def should_ignore_dir(dir_name: str) -> bool:
    """Check if directory name matches built-in ignore list."""
    if dir_name in BUILTIN_IGNORED_DIRS:
        return True
    if dir_name.endswith(".egg-info"):
        return True
    return False


def should_ignore_file(file_name: str) -> bool:
    """Check if file name matches built-in ignore list."""
    if file_name in BUILTIN_IGNORED_FILES:
        return True
    if file_name.startswith(".envguard") and (
        file_name.endswith(".json")
        or file_name.endswith(".yml")
        or file_name.endswith(".yaml")
    ):
        return True
    if file_name.endswith(".sarif"):
        return True
    if file_name.startswith("envguard-") and (
        file_name.endswith(".sarif")
        or file_name.endswith(".json")
        or file_name.endswith(".html")
        or file_name.endswith(".csv")
        or file_name.endswith(".md")
    ):
        return True
    return False


def is_path_ignored(
    rel_path: str,
    gitignore_spec: Optional[pathspec.PathSpec] = None,
    envguardignore_spec: Optional[pathspec.PathSpec] = None,
    config_exclude_spec: Optional[pathspec.PathSpec] = None,
    is_dir: bool = False,
) -> Tuple[bool, Optional[str]]:
    """Determine if a relative path is ignored and return the reason.

    Priority order:
    1. Built-in hardcoded rules
    2. .gitignore
    3. .envguardignore
    4. .envguard.yml exclude rules

    Returns (is_ignored, reason).
    """
    path_to_match = f"{rel_path}/" if is_dir and not rel_path.endswith("/") else rel_path

    # 1. Built-in check for path parts and filenames
    parts = rel_path.strip("/").split("/")
    for part in parts:
        if should_ignore_dir(part):
            return True, "builtin"

    if not is_dir:
        file_name = Path(rel_path).name
        if should_ignore_file(file_name):
            return True, "builtin"

    # 2. .gitignore
    if gitignore_spec and gitignore_spec.match_file(path_to_match):
        return True, "gitignore"

    # 3. .envguardignore
    if envguardignore_spec and envguardignore_spec.match_file(path_to_match):
        return True, "envguardignore"

    # 4. config exclude
    if config_exclude_spec and config_exclude_spec.match_file(path_to_match):
        return True, "config_exclude"

    return False, None
