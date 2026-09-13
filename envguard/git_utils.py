"""Safe Git integration utilities for EnvGuard v0.5.3.

Provides changed-file detection, staged-file inspection, base branch resolution,
and repository root identification with strict EnvGuard exception handling.
"""

from pathlib import Path
import subprocess
from typing import List, Optional

from envguard.exceptions import GitError


def run_git(args: List[str], cwd: Optional[Path] = None, check: bool = False) -> subprocess.CompletedProcess:
    """Safely execute a git subprocess command, wrapping OS errors in GitError."""
    work_dir = str(cwd) if cwd else None
    try:
        proc = subprocess.run(
            ["git"] + args,
            cwd=work_dir,
            capture_output=True,
            check=False,
        )
        if check and proc.returncode != 0:
            err_text = proc.stderr.decode("utf-8", errors="replace").strip()
            raise GitError(f"Git command failed (exit code {proc.returncode}): {err_text or 'Unknown error'}")
        return proc
    except FileNotFoundError:
        raise GitError("Git executable not found in system PATH.")
    except Exception as e:
        if isinstance(e, GitError):
            raise
        raise GitError(f"Failed to execute Git command: {e}")


def is_git_repository(path: Optional[Path] = None) -> bool:
    """Check if the given directory (or current directory) is inside a Git repository."""
    try:
        proc = run_git(["rev-parse", "--is-inside-work-tree"], cwd=path)
        return proc.returncode == 0 and proc.stdout.strip() == b"true"
    except Exception:
        return False


def get_git_root(path: Optional[Path] = None) -> Optional[Path]:
    """Get the root directory of the current Git repository."""
    try:
        proc = run_git(["rev-parse", "--show-toplevel"], cwd=path)
        if proc.returncode == 0:
            root_str = proc.stdout.decode("utf-8", errors="replace").strip()
            if root_str:
                return Path(root_str)
    except Exception:
        pass
    return None


def get_staged_files(repo_path: Optional[Path] = None) -> List[Path]:
    """Get list of Paths for all staged files in the Git index (added/copied/modified/renamed)."""
    root = get_git_root(repo_path) or (repo_path or Path.cwd())
    try:
        proc = run_git(
            ["diff", "--cached", "--name-only", "--diff-filter=ACMRT"],
            cwd=root,
            check=True,
        )
        raw = proc.stdout.decode("utf-8", errors="replace")
        paths: List[Path] = []
        for line in raw.splitlines():
            line = line.strip()
            if line:
                paths.append(root / line)
        return paths
    except GitError:
        raise
    except Exception as e:
        raise GitError(f"Failed to retrieve staged files: {e}")


def get_changed_files(
    base: str,
    head: str = "HEAD",
    repo_path: Optional[Path] = None,
) -> List[Path]:
    """Determine files changed between Git base reference and head.

    Executes 'git diff --name-only BASE...HEAD' with automatic two-dot fallback.
    Only returns files that exist on the filesystem.
    """
    root = get_git_root(repo_path) or (repo_path or Path.cwd())

    # Try 3-dot diff first (common ancestor)
    diff_args = ["diff", "--name-only", "--diff-filter=ACMRT", f"{base}...{head}"]
    proc = run_git(diff_args, cwd=root)

    # Fallback to 2-dot diff if 3-dot fails (e.g. shallow clone or orphan branch)
    if proc.returncode != 0:
        diff_args_fallback = ["diff", "--name-only", "--diff-filter=ACMRT", f"{base}..{head}"]
        proc = run_git(diff_args_fallback, cwd=root)

    if proc.returncode != 0:
        err_msg = proc.stderr.decode("utf-8", errors="replace").strip()
        raise GitError(f"Unable to compare Git references '{base}' and '{head}': {err_msg or 'Invalid reference'}")

    raw_output = proc.stdout.decode("utf-8", errors="replace")
    changed: List[Path] = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        candidate_file = root / line
        if candidate_file.is_file():
            changed.append(candidate_file)

    return changed


def get_default_base_branch(repo_path: Optional[Path] = None) -> Optional[str]:
    """Attempt to detect the primary base branch (e.g. origin/main, main, origin/master, master)."""
    root = get_git_root(repo_path) or (repo_path or Path.cwd())

    # 1. Check origin/HEAD symbolic ref
    try:
        proc = run_git(["rev-parse", "--abbrev-ref", "origin/HEAD"], cwd=root)
        if proc.returncode == 0:
            ref = proc.stdout.decode("utf-8", errors="replace").strip()
            if ref and not ref.endswith("/HEAD"):
                return ref
    except Exception:
        pass

    # 2. Check candidate branches in priority order
    candidates = ["origin/main", "main", "origin/master", "master"]
    for cand in candidates:
        try:
            proc = run_git(["rev-parse", "--verify", cand], cwd=root)
            if proc.returncode == 0:
                return cand
        except Exception:
            continue

    return None
