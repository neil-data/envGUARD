"""Git pre-push hook integration and commit scanning for EnvGuard v0.7.0.

Provides protocol parsing, ref/flag injection defense, commit range resolution,
and secret scanning across outgoing Git commits.
"""

from dataclasses import dataclass
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

from envguard.config import EnvGuardConfig, find_config_file, load_config
from envguard.exceptions import EnvGuardError, GitError
from envguard.git_handler import get_repo_root, run_git_command
from envguard.ignore import is_path_ignored, load_envguardignore
from envguard.patterns import Pattern, load_default_patterns
from envguard.scanner import (
    DEFAULT_MAX_BYTES,
    ScanFinding,
    compile_exclude_spec,
    scan_text,
)
from envguard.utils import is_binary_bytes

ZERO_SHA = "0" * 40


@dataclass
class PrePushRef:
    """Represents a single ref update line piped to Git's pre-push hook."""
    local_ref: str
    local_sha: str
    remote_ref: str
    remote_sha: str

    @property
    def is_delete(self) -> bool:
        """Return True if the push action deletes the remote ref."""
        return (
            self.local_sha == ZERO_SHA
            or self.local_ref == "(delete)"
            or not self.local_sha
        )

    @property
    def is_create(self) -> bool:
        """Return True if creating a new branch or tag on the remote."""
        return self.remote_sha == ZERO_SHA or not self.remote_sha

    @property
    def ref_name(self) -> str:
        """Human-readable short name of the local reference."""
        name = self.local_ref
        for prefix in ("refs/heads/", "refs/tags/", "refs/remotes/"):
            if name.startswith(prefix):
                return name[len(prefix):]
        return name


def validate_ref_field(value: str, field_name: str) -> None:
    """Defend against Git command injection via malicious ref names or SHAs."""
    if not value:
        return
    if value.startswith("-"):
        raise GitError(f"Invalid Git {field_name} '{value}': cannot begin with '-'")
    if "\0" in value:
        raise GitError(f"Invalid Git {field_name}: null byte detected")


def parse_pre_push_stdin(stream_content: str) -> List[PrePushRef]:
    """Parse stdin content provided by Git during a pre-push hook execution.

    Expected format per line:
        <local-ref> SP <local-sha> SP <remote-ref> SP <remote-sha> LF
    """
    refs: List[PrePushRef] = []
    for line in stream_content.splitlines():
        line = line.strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) != 4:
            # Skip unparseable lines or malformed input
            continue

        l_ref, l_sha, r_ref, r_sha = parts
        validate_ref_field(l_ref, "local-ref")
        validate_ref_field(l_sha, "local-sha")
        validate_ref_field(r_ref, "remote-ref")
        validate_ref_field(r_sha, "remote-sha")

        refs.append(
            PrePushRef(
                local_ref=l_ref,
                local_sha=l_sha,
                remote_ref=r_ref,
                remote_sha=r_sha,
            )
        )
    return refs


def dereference_commit(sha_or_ref: str, repo_path: Optional[Path] = None) -> str:
    """Dereference annotated tags or symbolic refs to underlying commit SHA."""
    if sha_or_ref == ZERO_SHA or not sha_or_ref:
        return sha_or_ref
    try:
        proc = run_git_command(["rev-parse", "--verify", f"{sha_or_ref}^{{commit}}"], cwd=repo_path)
        if proc.returncode == 0:
            val = proc.stdout.decode("utf-8", errors="replace").strip()
            if val:
                return val
    except Exception:
        pass
    return sha_or_ref


def determine_pushed_commits(
    ref: PrePushRef,
    remote_name: str = "origin",
    repo_path: Optional[Path] = None,
) -> List[str]:
    """Determine the list of commit SHAs to scan for an incoming push reference.

    For branch updates: commits in remote_sha..local_sha
    For new branches/tags: commits reachable from local_sha but not in remote tracking
    """
    if ref.is_delete:
        return []

    local_commit = dereference_commit(ref.local_sha, repo_path=repo_path)
    remote_commit = dereference_commit(ref.remote_sha, repo_path=repo_path)

    if not ref.is_create:
        # Range of commits between remote state and local state
        cmd = ["rev-list", f"{remote_commit}..{local_commit}", "--"]
        proc = run_git_command(cmd, cwd=repo_path)
        if proc.returncode == 0:
            raw = proc.stdout.decode("utf-8", errors="replace")
            commits = [c.strip() for c in raw.splitlines() if c.strip()]
            return commits
        # If rev-list fails (e.g. forced push / divergent history), inspect local commit
        return [local_commit]
    else:
        # Brand new branch or tag. Exclude commits already on the remote.
        clean_remote = remote_name if not remote_name.startswith("-") else "origin"
        cmd = ["rev-list", local_commit, "--not", f"--remotes={clean_remote}", "--"]
        proc = run_git_command(cmd, cwd=repo_path)
        if proc.returncode == 0:
            raw = proc.stdout.decode("utf-8", errors="replace")
            commits = [c.strip() for c in raw.splitlines() if c.strip()]
            if commits:
                return commits

        # If --remotes=<remote_name> had no matching refs, exclude any known remotes
        cmd2 = ["rev-list", local_commit, "--not", "--remotes", "--"]
        proc2 = run_git_command(cmd2, cwd=repo_path)
        if proc2.returncode == 0:
            raw2 = proc2.stdout.decode("utf-8", errors="replace")
            commits2 = [c.strip() for c in raw2.splitlines() if c.strip()]
            if commits2:
                return commits2

        # Initial repo push or orphan branch: rev-list local_commit
        cmd3 = ["rev-list", local_commit, "--"]
        proc3 = run_git_command(cmd3, cwd=repo_path)
        if proc3.returncode == 0:
            raw3 = proc3.stdout.decode("utf-8", errors="replace")
            commits3 = [c.strip() for c in raw3.splitlines() if c.strip()]
            if commits3:
                return commits3

        return [local_commit]


def get_commit_changed_files(commit_sha: str, repo_path: Optional[Path] = None) -> List[str]:
    """Retrieve list of files added/modified/renamed in a specific commit.

    Uses 'git diff-tree -r --root --no-commit-id --name-only --diff-filter=ACMRT <commit> --'
    """
    validate_ref_field(commit_sha, "commit SHA")
    proc = run_git_command(
        ["diff-tree", "-r", "--root", "--no-commit-id", "--name-only", "--diff-filter=ACMRT", commit_sha, "--"],
        cwd=repo_path,
    )
    if proc.returncode != 0:
        return []
    raw = proc.stdout.decode("utf-8", errors="replace")
    return [line.strip() for line in raw.splitlines() if line.strip()]


def get_commit_file_bytes(commit_sha: str, rel_path: str, repo_path: Optional[Path] = None) -> Optional[bytes]:
    """Retrieve file bytes directly from Git object store for a specific commit."""
    validate_ref_field(commit_sha, "commit SHA")
    if "\0" in rel_path or rel_path.startswith("-"):
        return None
    git_path = rel_path.replace("\\", "/")
    proc = run_git_command(["show", f"{commit_sha}:{git_path}"], cwd=repo_path)
    if proc.returncode == 0:
        return proc.stdout
    return None


def scan_commit_files(
    commits: List[str],
    patterns: List[Pattern],
    repo_path: Optional[Path] = None,
    max_file_size_bytes: int = DEFAULT_MAX_BYTES,
    exclude_patterns: Optional[List[str]] = None,
    stats: Optional[Dict[str, int]] = None,
    advanced_config: Optional[Any] = None,
) -> Tuple[List[ScanFinding], int]:
    """Scan all files changed across a set of commits directly from Git objects."""
    target_repo = repo_path or Path.cwd()
    envguardignore_spec = load_envguardignore(target_repo)
    config_exclude_spec = compile_exclude_spec(exclude_patterns or [])

    findings: List[ScanFinding] = []
    seen_commit_files: Set[Tuple[str, str]] = set()
    total_files_scanned = 0

    for commit in commits:
        changed_files = get_commit_changed_files(commit, repo_path=target_repo)
        for rel_path in changed_files:
            key = (commit, rel_path)
            if key in seen_commit_files:
                continue
            seen_commit_files.add(key)

            ignored, _ = is_path_ignored(
                rel_path=rel_path,
                gitignore_spec=None,
                envguardignore_spec=envguardignore_spec,
                config_exclude_spec=config_exclude_spec,
                is_dir=False,
            )
            if ignored:
                continue

            raw_bytes = get_commit_file_bytes(commit, rel_path, repo_path=target_repo)
            if raw_bytes is None:
                continue

            if len(raw_bytes) > max_file_size_bytes:
                continue

            if is_binary_bytes(raw_bytes):
                continue

            total_files_scanned += 1
            content = raw_bytes.decode("utf-8", errors="replace")
            file_findings = scan_text(
                text=content,
                file_path_str=rel_path,
                patterns=patterns,
                stats=stats,
                advanced_config=advanced_config,
            )
            findings.extend(file_findings)

    return findings, total_files_scanned
