"""Git pre-commit hook installer and manager for EnvGuard."""

import os
from pathlib import Path
import stat
from typing import Optional, Tuple

from envguard.git_handler import get_hooks_dir, is_git_repo

HOOK_MARKER_BEGIN = "# BEGIN ENVGUARD HOOK"
HOOK_MARKER_END = "# END ENVGUARD HOOK"

HOOK_PAYLOAD = f"""{HOOK_MARKER_BEGIN}
envguard check
STATUS=$?

if [ $STATUS -ne 0 ]; then
    exit $STATUS
fi
{HOOK_MARKER_END}"""


def is_hook_installed(repo_path: Optional[Path] = None) -> bool:
    """Check if the EnvGuard hook is present in .git/hooks/pre-commit."""
    hooks_dir = get_hooks_dir(repo_path)
    if not hooks_dir:
        return False
    hook_file = hooks_dir / "pre-commit"
    if not hook_file.is_file():
        return False
    try:
        content = hook_file.read_text(encoding="utf-8", errors="replace")
        return HOOK_MARKER_BEGIN in content
    except Exception:
        return False


def make_executable(filepath: Path) -> None:
    """Make a file executable (chmod +x) on Unix-like systems."""
    try:
        current_mode = filepath.stat().st_mode
        filepath.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        # On Windows or restricted filesystems, chmod may not be supported or needed
        pass


def install_pre_commit_hook(repo_path: Optional[Path] = None) -> Tuple[bool, str]:
    """Install or update the EnvGuard pre-commit hook safely.

    Returns (success: bool, message: str).
    """
    if not is_git_repo(repo_path):
        return False, "Not a Git repository. Cannot install pre-commit hook."

    hooks_dir = get_hooks_dir(repo_path)
    if not hooks_dir:
        return False, "Could not locate Git hooks directory."

    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_file = hooks_dir / "pre-commit"

    if hook_file.exists():
        try:
            current_content = hook_file.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return False, f"Failed to read existing pre-commit hook: {e}"

        if HOOK_MARKER_BEGIN in current_content and HOOK_MARKER_END in current_content:
            # Replace existing EnvGuard block safely to ensure it has latest payload
            start_idx = current_content.find(HOOK_MARKER_BEGIN)
            end_idx = current_content.find(HOOK_MARKER_END) + len(HOOK_MARKER_END)
            new_content = current_content[:start_idx] + HOOK_PAYLOAD + current_content[end_idx:]
            hook_file.write_text(new_content, encoding="utf-8")
            make_executable(hook_file)
            return True, "EnvGuard pre-commit hook was already installed and has been refreshed."
        else:
            # Append safely to existing hook
            separator = "\n\n" if not current_content.endswith("\n") else "\n"
            new_content = current_content + separator + HOOK_PAYLOAD + "\n"
            hook_file.write_text(new_content, encoding="utf-8")
            make_executable(hook_file)
            return True, "Safely appended EnvGuard pre-commit hook to existing pre-commit script."
    else:
        # Create new pre-commit script with shebang
        new_content = f"#!/bin/sh\n\n{HOOK_PAYLOAD}\n"
        hook_file.write_text(new_content, encoding="utf-8")
        make_executable(hook_file)
        return True, "Created new .git/hooks/pre-commit with EnvGuard hook."
