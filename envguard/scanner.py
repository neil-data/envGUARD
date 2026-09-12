"""Secret scanner engine for working directory and staged Git content with performance controls."""

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import pathspec

from envguard.git_handler import get_staged_file_bytes, get_staged_files
from envguard.patterns import Pattern, load_default_patterns
from envguard.utils import is_binary_bytes, is_binary_file, mask_secret

IGNORED_DIRECTORIES: Set[str] = {
    ".git",
    "venv",
    ".venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".idea",
    ".vscode",
    "dist",
    "build",
    "egg-info",
}

DEFAULT_MAX_BYTES = 5 * 1024 * 1024  # 5 MB


def compute_fingerprint(rule_id: str, file_path: str, raw_secret: str) -> str:
    """Compute SHA-256 fingerprint from rule_id, normalized file path, and raw secret.

    Never exposes raw secret outside of this calculation.
    """
    normalized_path = file_path.replace("\\", "/").lstrip("./")
    payload = f"{rule_id}:{normalized_path}:{raw_secret}".encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    return f"sha256:{digest}"


@dataclass
class ScanFinding:
    rule_id: str
    rule_name: str
    severity: str  # "HIGH", "MEDIUM", "LOW"
    file_path: str
    line_number: int
    raw_value: str
    masked_value: str
    fingerprint: str
    line_snippet: str = ""

    @property
    def confidence(self) -> str:
        """Backwards compatibility alias for severity."""
        return self.severity

    @property
    def pattern_name(self) -> str:
        """Backwards compatibility alias for rule_name."""
        return self.rule_name

    @property
    def is_blocking(self) -> bool:
        """Default blocking check for HIGH and MEDIUM findings."""
        return self.severity in ("HIGH", "MEDIUM")

    def is_blocking_for(self, block_on: List[str]) -> bool:
        """Check if finding is blocking according to configured block_on list."""
        return self.severity in block_on


@dataclass
class ScanReport:
    findings: List[ScanFinding] = field(default_factory=list)
    skipped_large_files: List[str] = field(default_factory=list)
    skipped_binary_files: List[str] = field(default_factory=list)
    total_files_scanned: int = 0


def scan_text(text: str, file_path_str: str, patterns: List[Pattern]) -> List[ScanFinding]:
    """Scan string content line by line using provided patterns."""
    findings: List[ScanFinding] = []
    lines = text.splitlines()

    for line_idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        for pattern in patterns:
            if not pattern.enabled:
                continue

            for secret_val, start, end in pattern.find_matches(line):
                fp = compute_fingerprint(pattern.id, file_path_str, secret_val)
                findings.append(
                    ScanFinding(
                        rule_id=pattern.id,
                        rule_name=pattern.name,
                        severity=pattern.severity,
                        file_path=file_path_str,
                        line_number=line_idx,
                        raw_value=secret_val,
                        masked_value=mask_secret(secret_val),
                        fingerprint=fp,
                        line_snippet=stripped,
                    )
                )

    return findings


def load_root_gitignore(base_dir: Path) -> Optional[pathspec.PathSpec]:
    """Load root .gitignore file if present and compile into a PathSpec."""
    gitignore_path = base_dir / ".gitignore"
    if gitignore_path.is_file():
        try:
            lines = gitignore_path.read_text(encoding="utf-8", errors="replace").splitlines()
            return pathspec.PathSpec.from_lines("gitignore", lines)
        except Exception:
            return None
    return None


def compile_exclude_spec(exclude_patterns: List[str]) -> Optional[pathspec.PathSpec]:
    """Compile custom exclude patterns from config into a PathSpec."""
    if not exclude_patterns:
        return None
    try:
        return pathspec.PathSpec.from_lines("gitignore", exclude_patterns)
    except Exception:
        return None


def scan_file_streaming(
    file_path: Path,
    rel_path_str: str,
    patterns: List[Pattern],
    max_file_size_bytes: int = DEFAULT_MAX_BYTES,
) -> Tuple[List[ScanFinding], Optional[str]]:
    """Scan a single file line by line without loading the entire file into memory.

    Returns (findings, skip_reason).
    """
    try:
        # Size check before reading
        file_size = file_path.stat().st_size
        if file_size > max_file_size_bytes:
            return [], f"oversized ({file_size / (1024*1024):.2f} MB)"

        # Binary check
        if is_binary_file(file_path):
            return [], "binary"

        findings: List[ScanFinding] = []
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line_idx, line in enumerate(f, start=1):
                stripped = line.strip()
                if not stripped:
                    continue

                for pattern in patterns:
                    if not pattern.enabled:
                        continue

                    for secret_val, start, end in pattern.find_matches(line):
                        fp = compute_fingerprint(pattern.id, rel_path_str, secret_val)
                        findings.append(
                            ScanFinding(
                                rule_id=pattern.id,
                                rule_name=pattern.name,
                                severity=pattern.severity,
                                file_path=rel_path_str,
                                line_number=line_idx,
                                raw_value=secret_val,
                                masked_value=mask_secret(secret_val),
                                fingerprint=fp,
                                line_snippet=stripped,
                            )
                        )
        return findings, None
    except Exception as e:
        return [], f"read error: {e}"


def scan_directory(
    directory: Path,
    patterns: Optional[List[Pattern]] = None,
    respect_gitignore: bool = True,
    exclude_patterns: Optional[List[str]] = None,
    max_file_size_bytes: int = DEFAULT_MAX_BYTES,
    verbose_log: Optional[List[str]] = None,
    stats: Optional[Dict[str, int]] = None,
) -> List[ScanFinding]:
    """Scan current working directory recursively with streaming and size protection."""
    if patterns is None:
        patterns = load_default_patterns()

    if stats is not None:
        stats.setdefault("files_scanned", 0)
        stats.setdefault("files_skipped", 0)

    if directory.is_file():
        findings, skip_reason = scan_file_streaming(
            file_path=directory,
            rel_path_str=directory.name,
            patterns=patterns,
            max_file_size_bytes=max_file_size_bytes,
        )
        if stats is not None:
            if skip_reason:
                stats["files_skipped"] += 1
            else:
                stats["files_scanned"] += 1
        return findings

    spec = load_root_gitignore(directory) if respect_gitignore else None
    exclude_spec = compile_exclude_spec(exclude_patterns or [])

    all_findings: List[ScanFinding] = []

    for root, dirs, files in os.walk(directory):
        root_path = Path(root)

        # In-place modify dirs to avoid descending into ignored directories
        dirs[:] = [
            d for d in dirs
            if d not in IGNORED_DIRECTORIES and not d.endswith(".egg-info")
        ]

        # Check gitignore and custom excludes for directory paths
        surviving_dirs = []
        for d in dirs:
            rel_dir = (root_path / d).relative_to(directory).as_posix()
            dir_posix = f"{rel_dir}/"
            if spec and spec.match_file(dir_posix):
                if verbose_log is not None:
                    verbose_log.append(f"Skipped gitignored directory: {rel_dir}")
                continue
            if exclude_spec and exclude_spec.match_file(dir_posix):
                if verbose_log is not None:
                    verbose_log.append(f"Skipped excluded directory: {rel_dir}")
                continue
            surviving_dirs.append(d)
        dirs[:] = surviving_dirs

        for filename in files:
            file_path = root_path / filename
            rel_file = file_path.relative_to(directory).as_posix()

            # Check if file is ignored by .gitignore
            if spec and spec.match_file(rel_file):
                if stats is not None:
                    stats["files_skipped"] += 1
                continue

            # Check if file is ignored by custom config exclude
            if exclude_spec and exclude_spec.match_file(rel_file):
                if stats is not None:
                    stats["files_skipped"] += 1
                if verbose_log is not None:
                    verbose_log.append(f"Skipped excluded file: {rel_file}")
                continue

            findings, skip_reason = scan_file_streaming(
                file_path=file_path,
                rel_path_str=rel_file,
                patterns=patterns,
                max_file_size_bytes=max_file_size_bytes,
            )

            if skip_reason:
                if stats is not None:
                    stats["files_skipped"] += 1
                if verbose_log is not None:
                    verbose_log.append(f"Skipped {skip_reason}: {rel_file}")
            else:
                if stats is not None:
                    stats["files_scanned"] += 1

            all_findings.extend(findings)

    return all_findings


def scan_staged(
    repo_path: Optional[Path] = None,
    patterns: Optional[List[Pattern]] = None,
    max_file_size_bytes: int = DEFAULT_MAX_BYTES,
    exclude_patterns: Optional[List[str]] = None,
) -> List[ScanFinding]:
    """Scan staged files directly from Git index using git show :path."""
    if patterns is None:
        patterns = load_default_patterns()

    exclude_spec = compile_exclude_spec(exclude_patterns or [])
    staged_files = get_staged_files(repo_path)
    all_findings: List[ScanFinding] = []

    for rel_path in staged_files:
        # Check custom config exclude
        if exclude_spec and exclude_spec.match_file(rel_path):
            continue

        try:
            raw_bytes = get_staged_file_bytes(rel_path, repo_path)
            if raw_bytes is None:
                continue

            if len(raw_bytes) > max_file_size_bytes:
                continue

            # Skip binary staged files
            if is_binary_bytes(raw_bytes):
                continue

            content = raw_bytes.decode("utf-8", errors="replace")
            findings = scan_text(content, rel_path, patterns)
            all_findings.extend(findings)
        except Exception:
            # Handle decoding or git errors gracefully for individual files
            continue

    return all_findings
