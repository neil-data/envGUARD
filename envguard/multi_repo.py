"""Multi-repository scanning engine for EnvGuard v0.6.0.

Provides independent, tolerant, and secure multi-repository scanning:
- Strict path validation against argument injection (leading '-' rejection).
- Independent configuration and organization policy resolution per repository.
- Error isolation: continuing scans across remaining repositories upon partial failures.
- Unified reporting and exit code computation.
"""

from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

from envguard.baseline import DEFAULT_BASELINE_FILENAME, load_baseline
from envguard.config import EnvGuardConfig, load_config
from envguard.exceptions import EnvGuardError, ScanError
from envguard.patterns import load_default_patterns
from envguard.scanner import ScanFinding, scan_directory


def validate_repo_path(raw_path: str) -> Path:
    """Validate a repository path string against argument injection and filesystem hazards.

    Raises:
        ScanError: If path starts with '-', contains null bytes, or is empty.
    """
    cleaned = raw_path.strip()
    if not cleaned:
        raise ScanError("Repository path cannot be empty.")

    if cleaned.startswith("-"):
        raise ScanError(
            f"Invalid repository path '{cleaned}': path cannot begin with '-'. "
            "Flag injection is prohibited."
        )

    if "\0" in cleaned:
        raise ScanError(f"Invalid repository path '{cleaned}': path contains null byte.")

    return Path(cleaned)


@dataclass
class RepoScanResult:
    """Scan results for an individual repository in a multi-repo scan."""
    name: str
    path: Path
    status: str  # "passed", "failed", "error"
    files_scanned: int = 0
    files_skipped: int = 0
    findings: List[ScanFinding] = field(default_factory=list)
    suppressed_count: int = 0
    error: Optional[str] = None
    config_warnings: List[str] = field(default_factory=list)
    has_org_policy: bool = False

    @property
    def has_blocking_findings(self) -> bool:
        """True if repository has active findings that trigger blocking."""
        return any(f.blocked_by is not None for f in self.findings)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "LOW")


@dataclass
class MultiRepoScanResult:
    """Aggregated scan results across all scanned repositories."""
    repositories: List[RepoScanResult] = field(default_factory=list)

    @property
    def total_repos(self) -> int:
        return len(self.repositories)

    @property
    def passed_repos(self) -> int:
        return sum(1 for r in self.repositories if r.status == "passed")

    @property
    def failed_repos(self) -> int:
        return sum(1 for r in self.repositories if r.status == "failed")

    @property
    def error_repos(self) -> int:
        return sum(1 for r in self.repositories if r.status == "error")

    @property
    def all_findings(self) -> List[ScanFinding]:
        findings: List[ScanFinding] = []
        for r in self.repositories:
            findings.extend(r.findings)
        return findings

    @property
    def total_findings(self) -> int:
        return len(self.all_findings)

    @property
    def total_files_scanned(self) -> int:
        return sum(r.files_scanned for r in self.repositories)

    @property
    def total_files_skipped(self) -> int:
        return sum(r.files_skipped for r in self.repositories)

    @property
    def total_suppressed(self) -> int:
        return sum(r.suppressed_count for r in self.repositories)

    @property
    def has_blocking_findings(self) -> bool:
        return any(r.has_blocking_findings for r in self.repositories)

    @property
    def has_errors(self) -> bool:
        return self.error_repos > 0

    @property
    def exit_code(self) -> int:
        """Calculate final exit code:

        0: Clean (all repositories passed, no blocking findings, no errors)
        1: Security failure (one or more repositories had blocking findings)
        2: Execution / configuration errors occurred (and no blocking findings)
        """
        if self.has_blocking_findings:
            return 1
        if self.has_errors:
            return 2
        return 0


def parse_repo_targets(repo_args: List[str]) -> List[Path]:
    """Parse and safely validate a list of repository target arguments (supports comma separation)."""
    targets: List[Path] = []
    for arg in repo_args:
        # Split by comma if present
        parts = [p.strip() for p in arg.split(",") if p.strip()]
        for part in parts:
            validated = validate_repo_path(part)
            targets.append(validated)
    return targets


def scan_multiple_repositories(
    repo_targets: List[Path],
    verbose: bool = False,
    progress_callback: Optional[Callable[[str, int, Optional[int]], None]] = None,
) -> MultiRepoScanResult:
    """Execute independent security scan across multiple repositories.

    Each repository resolves its own configuration, organization policy,
    and baseline independently. Any failure in one repository is captured
    without terminating remaining scans.
    """
    result = MultiRepoScanResult()

    for target_path in repo_targets:
        repo_name = target_path.name or str(target_path)
        resolved_root = target_path.resolve()

        if not target_path.exists():
            result.repositories.append(
                RepoScanResult(
                    name=repo_name,
                    path=target_path,
                    status="error",
                    error=f"Repository path does not exist: {target_path}",
                )
            )
            continue

        if not target_path.is_dir():
            result.repositories.append(
                RepoScanResult(
                    name=repo_name,
                    path=target_path,
                    status="error",
                    error=f"Repository path is not a directory: {target_path}",
                )
            )
            continue

        # Execute scan pipeline in isolation
        try:
            config = load_config(root_dir=resolved_root)
            has_org = config.org_config is not None

            patterns = load_default_patterns(
                disabled_rules=config.disabled_rules,
                severity_overrides=config.severity_overrides,
            )

            # Baseline loading
            baseline_file = resolved_root / DEFAULT_BASELINE_FILENAME
            suppressed_fps: Set[str] = set()
            if baseline_file.is_file():
                try:
                    suppressed_fps = load_baseline(baseline_file)
                except Exception:
                    suppressed_fps = set()

            stats: Dict[str, int] = {"files_scanned": 0, "files_skipped": 0}
            raw_findings = scan_directory(
                directory=resolved_root,
                patterns=patterns,
                respect_gitignore=True,
                exclude_patterns=config.exclude,
                max_file_size_bytes=config.max_file_size_bytes,
                stats=stats,
                advanced_config=config.advanced_detection,
                progress_callback=progress_callback,
            )

            # Filter baseline suppressions and tag findings
            active_findings: List[ScanFinding] = []
            suppressed_count = 0
            for f in raw_findings:
                if f.fingerprint in suppressed_fps:
                    suppressed_count += 1
                else:
                    f.repository = repo_name
                    f.blocked_by = f.determine_blocking(
                        local_block_on=config.local_block_on or config.block_on,
                        org_block_on=config.org_config.block_on if config.org_config else None,
                    )
                    active_findings.append(f)

            has_blocking = any(f.blocked_by is not None for f in active_findings)
            status = "failed" if has_blocking else "passed"

            result.repositories.append(
                RepoScanResult(
                    name=repo_name,
                    path=target_path,
                    status=status,
                    files_scanned=stats.get("files_scanned", 0),
                    files_skipped=stats.get("files_skipped", 0),
                    findings=active_findings,
                    suppressed_count=suppressed_count,
                    config_warnings=config.warnings,
                    has_org_policy=has_org,
                )
            )

        except Exception as e:
            result.repositories.append(
                RepoScanResult(
                    name=repo_name,
                    path=target_path,
                    status="error",
                    error=str(e),
                )
            )

    return result
