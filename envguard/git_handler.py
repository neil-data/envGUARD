"""Git integration helper functions for EnvGuard."""

from pathlib import Path
import subprocess
from typing import List, Optional

from envguard.git_utils import (
    get_changed_files,
    get_default_base_branch,
    is_git_repository,
    run_git,
)


def run_git_command(args: List[str], cwd: Optional[Path] = None, check: bool = False) -> subprocess.CompletedProcess:
    """Run a git command safely and return CompletedProcess."""
    work_dir = str(cwd) if cwd else None
    return subprocess.run(
        ["git"] + args,
        cwd=work_dir,
        capture_output=True,
        check=check,
    )


def is_git_repo(path: Optional[Path] = None) -> bool:
    """Check if the given directory (or current dir) is inside a Git repository."""
    try:
        proc = run_git_command(["rev-parse", "--is-inside-work-tree"], cwd=path)
        return proc.returncode == 0 and proc.stdout.strip() == b"true"
    except Exception:
        return False


def get_repo_root(path: Optional[Path] = None) -> Optional[Path]:
    """Get the root directory of the current Git repository."""
    try:
        proc = run_git_command(["rev-parse", "--show-toplevel"], cwd=path)
        if proc.returncode == 0:
            root_str = proc.stdout.decode("utf-8", errors="replace").strip()
            return Path(root_str)
    except Exception:
        pass
    return None


def get_staged_files(repo_path: Optional[Path] = None) -> List[str]:
    """Get relative paths of all staged files in the Git index."""
    try:
        # Filter ACMRT: Added, Copied, Modified, Renamed, Type changed (exclude Deleted)
        proc = run_git_command(
            ["diff", "--cached", "--name-only", "--diff-filter=ACMRT"],
            cwd=repo_path,
        )
        if proc.returncode != 0:
            return []

        raw_output = proc.stdout.decode("utf-8", errors="replace")
        lines = [line.strip() for line in raw_output.splitlines() if line.strip()]
        return lines
    except Exception:
        return []


def get_staged_file_bytes(rel_path: str, repo_path: Optional[Path] = None) -> Optional[bytes]:
    """Retrieve raw bytes of a file directly from the Git index using git show :<path>."""
    try:
        # Note: on Windows git expects forward slashes in object names
        git_path = rel_path.replace("\\", "/")
        proc = run_git_command(["show", f":{git_path}"], cwd=repo_path)
        if proc.returncode == 0:
            return proc.stdout
        return None
    except Exception:
        return None


def is_env_tracked(repo_path: Optional[Path] = None, filename: str = ".env") -> bool:
    """Check if .env is tracked in the Git repository index or commit history."""
    try:
        proc = run_git_command(["ls-files", "--error-unmatch", filename], cwd=repo_path)
        return proc.returncode == 0
    except Exception:
        return False


def get_hooks_dir(repo_path: Optional[Path] = None) -> Optional[Path]:
    """Locate the Git hooks directory for the repository."""
    try:
        proc = run_git_command(["rev-parse", "--git-path", "hooks"], cwd=repo_path)
        if proc.returncode == 0:
            raw = proc.stdout.decode("utf-8", errors="replace").strip()
            hooks_path = Path(raw)
            if not hooks_path.is_absolute():
                root = get_repo_root(repo_path) or (repo_path or Path.cwd())
                hooks_path = root / hooks_path
            return hooks_path
    except Exception:
        pass

    # Fallback to standard .git/hooks
    root = get_repo_root(repo_path) or (repo_path or Path.cwd())
    candidate = root / ".git" / "hooks"
    return candidate
