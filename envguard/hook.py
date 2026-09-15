"""Git hook installer and manager for EnvGuard v0.7.0.

Supports pre-commit and pre-push hooks with non-destructive marker-based
installation and automatic updates.
"""

from pathlib import Path
import stat
from typing import Any, Optional, Tuple

from envguard.git_handler import get_hooks_dir, is_git_repo

HOOK_MARKER_BEGIN = "# BEGIN ENVGUARD HOOK"
HOOK_MARKER_END = "# END ENVGUARD HOOK"

PRE_PUSH_MARKER_BEGIN = "# BEGIN ENVGUARD PRE-PUSH HOOK"
PRE_PUSH_MARKER_END = "# END ENVGUARD PRE-PUSH HOOK"

PRE_COMMIT_PAYLOAD = f"""{HOOK_MARKER_BEGIN}
envguard check
STATUS=$?

if [ $STATUS -ne 0 ]; then
    exit $STATUS
fi
{HOOK_MARKER_END}"""

PRE_PUSH_PAYLOAD = f"""{PRE_PUSH_MARKER_BEGIN}
envguard pre-push "$@"
STATUS=$?

if [ $STATUS -ne 0 ]; then
    exit $STATUS
fi
{PRE_PUSH_MARKER_END}"""

HOOK_PAYLOAD = PRE_COMMIT_PAYLOAD


def is_hook_installed(
    repo_path: Optional[Any] = None,
    hook_type: str = "pre-commit",
) -> bool:
    """Check if the EnvGuard hook is present in .git/hooks/<hook_type>."""
    if isinstance(repo_path, str) and repo_path in ("pre-commit", "pre-push"):
        hook_type = repo_path
        repo_path = None

    hooks_dir = get_hooks_dir(repo_path)
    if not hooks_dir:
        return False
    hook_file = hooks_dir / hook_type
    if not hook_file.is_file():
        return False
    try:
        content = hook_file.read_text(encoding="utf-8", errors="replace")
        marker = PRE_PUSH_MARKER_BEGIN if hook_type == "pre-push" else HOOK_MARKER_BEGIN
        return marker in content
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


def install_git_hook(
    hook_type: str = "pre-commit",
    repo_path: Optional[Path] = None,
) -> Tuple[bool, str]:
    """Install or update an EnvGuard Git hook safely.

    Supported hook_types: "pre-commit", "pre-push".
    Returns (success: bool, message: str).
    """
    if hook_type not in ("pre-commit", "pre-push"):
        return False, f"Unsupported hook type '{hook_type}'. Must be 'pre-commit' or 'pre-push'."

    if not is_git_repo(repo_path):
        return False, f"Not a Git repository. Cannot install {hook_type} hook."

    hooks_dir = get_hooks_dir(repo_path)
    if not hooks_dir:
        return False, "Could not locate Git hooks directory."

    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_file = hooks_dir / hook_type

    begin_marker = PRE_PUSH_MARKER_BEGIN if hook_type == "pre-push" else HOOK_MARKER_BEGIN
    end_marker = PRE_PUSH_MARKER_END if hook_type == "pre-push" else HOOK_MARKER_END
    payload = PRE_PUSH_PAYLOAD if hook_type == "pre-push" else PRE_COMMIT_PAYLOAD

    if hook_file.exists():
        try:
            current_content = hook_file.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return False, f"Failed to read existing {hook_type} hook: {e}"

        if begin_marker in current_content and end_marker in current_content:
            # Replace existing EnvGuard block safely to ensure it has latest payload
            start_idx = current_content.find(begin_marker)
            end_idx = current_content.find(end_marker) + len(end_marker)
            new_content = current_content[:start_idx] + payload + current_content[end_idx:]
            hook_file.write_text(new_content, encoding="utf-8")
            make_executable(hook_file)
            return True, f"EnvGuard {hook_type} hook was already installed and has been refreshed."
        else:
            # Append safely to existing hook
            separator = "\n\n" if not current_content.endswith("\n") else "\n"
            new_content = current_content + separator + payload + "\n"
            hook_file.write_text(new_content, encoding="utf-8")
            make_executable(hook_file)
            return True, f"Safely appended EnvGuard {hook_type} hook to existing {hook_type} script."
    else:
        # Create new script with shebang
        new_content = f"#!/bin/sh\n\n{payload}\n"
        hook_file.write_text(new_content, encoding="utf-8")
        make_executable(hook_file)
        return True, f"Created new .git/hooks/{hook_type} with EnvGuard hook."


def install_pre_commit_hook(repo_path: Optional[Path] = None) -> Tuple[bool, str]:
    """Install or update the EnvGuard pre-commit hook safely."""
    return install_git_hook("pre-commit", repo_path=repo_path)


def install_pre_push_hook(repo_path: Optional[Path] = None) -> Tuple[bool, str]:
    """Install or update the EnvGuard pre-push hook safely."""
    return install_git_hook("pre-push", repo_path=repo_path)
