"""Secret scanning engine for EnvGuard v0.4.0.

Provides line-by-line scanning, streaming file checks, Git staged-content inspection,
multi-signal scoring, JWT validation, Shannon entropy analysis, and false-positive filtering.
"""

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import pathspec

from envguard.detectors import (
    AdvancedDetectionConfig,
    DetectionCandidate,
    ScoredResult,
    detect_entropy_candidates,
    detect_jwt_candidates,
    detect_regex_candidates,
    score_candidate,
)
from envguard.detectors.scoring import SEVERITY_ORDER
from envguard.git_handler import get_staged_file_bytes, get_staged_files
from envguard.ignore import BUILTIN_IGNORED_DIRS, is_path_ignored, load_envguardignore
from envguard.patterns import Pattern, load_default_patterns
from envguard.suppression import SuppressionManager, parse_suppressions_from_lines
from envguard.utils import is_binary_bytes, is_binary_file, mask_secret

IGNORED_DIRECTORIES: Set[str] = BUILTIN_IGNORED_DIRS

DEFAULT_MAX_BYTES = 5 * 1024 * 1024  # 5 MB


def compute_fingerprint(rule_id: str, file_path: str, raw_secret: str) -> str:
    """Compute SHA-256 fingerprint from rule_id, normalized file path, and raw secret.

    Never exposes raw secret outside of this calculation.
    """
    normalized_path = file_path.replace("\\", "/").lstrip("./")
    payload = f"{rule_id}:{normalized_path}:{raw_secret}".encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    return f"sha256:{digest}"


def determine_blocking(
    severity: str,
    local_block_on: Any,
    org_block_on: Optional[Any] = None,
) -> Optional[str]:
    """Determine if a severity is blocked and identify the blocking policy source.

    Returns:
        "organization & local policy", "organization policy", "local policy", or None.
    """
    in_org = org_block_on is not None and severity in org_block_on
    in_local = severity in local_block_on

    if in_org and in_local:
        return "organization & local policy"
    elif in_org:
        return "organization policy"
    elif in_local:
        return "local policy"
    return None


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
    detection_signals: List[str] = field(default_factory=list)
    entropy: Optional[float] = None
    provider: Optional[str] = None
    repository: Optional[str] = None
    blocked_by: Optional[str] = None

    @property
    def confidence(self) -> str:
        """Backwards compatibility alias for severity."""
        return self.severity

    @property
    def fingerprint_hash(self) -> str:
        """Return the raw 64-character SHA-256 hexadecimal digest."""
        if self.fingerprint.startswith("sha256:"):
            return self.fingerprint[7:]
        return self.fingerprint

    @property
    def pattern_name(self) -> str:
        """Backwards compatibility alias for rule_name."""
        return self.rule_name

    @property
    def is_blocking(self) -> bool:
        """Default blocking check for HIGH and MEDIUM findings."""
        return self.severity in ("HIGH", "MEDIUM")

    def determine_blocking(
        self,
        local_block_on: Any,
        org_block_on: Optional[Any] = None,
    ) -> Optional[str]:
        """Determine if this finding is blocked and identify the blocking policy source.

        Returns:
            "organization & local policy", "organization policy", "local policy", or None.
        """
        return determine_blocking(self.severity, local_block_on, org_block_on)

    def is_blocking_for(
        self,
        block_on: List[str],
        org_block_on: Optional[List[str]] = None,
    ) -> bool:
        """Check if finding is blocking according to configured block_on list and optional org policy."""
        if org_block_on is not None:
            return self.determine_blocking(block_on, org_block_on) is not None
        return self.severity in block_on


@dataclass
class ScanReport:
    findings: List[ScanFinding] = field(default_factory=list)
    skipped_large_files: List[str] = field(default_factory=list)
    skipped_binary_files: List[str] = field(default_factory=list)
    total_files_scanned: int = 0


def deduplicate_and_merge_candidates(
    scored_candidates: List[Tuple[DetectionCandidate, ScoredResult]],
    line_snippet: str,
    line_number: int,
    file_path: Optional[str] = None,
    file_path_str: Optional[str] = None,
    suppression_mgr: Optional[SuppressionManager] = None,
    stats: Optional[Dict[str, int]] = None,
) -> List[ScanFinding]:
    """Group overlapping candidates on a line, pick specific over generic, and merge signals."""
    if not scored_candidates:
        return []
    actual_file_path = file_path_str or file_path or ""

    # Cluster candidates that share identical or overlapping secret values
    clusters: List[List[Tuple[DetectionCandidate, ScoredResult]]] = []
    for cand, scored in scored_candidates:
        matched_cluster = None
        c_val = cand.value.strip().strip("'\"")
        for cluster in clusters:
            for cl_cand, _ in cluster:
                cl_val = cl_cand.value.strip().strip("'\"")
                if c_val == cl_val or c_val in cl_val or cl_val in c_val:
                    matched_cluster = cluster
                    break
            if matched_cluster is not None:
                break

        if matched_cluster is not None:
            matched_cluster.append((cand, scored))
        else:
            clusters.append([(cand, scored)])

    findings: List[ScanFinding] = []
    for cluster in clusters:
        # Deterministic precedence:
        # 1. Specific provider regex (score 50) e.g. aws-*, google-*, github-*, gitlab-*, npm-*, pypi-*, slack-*, discord-*, azure-*, stripe-*
        # 2. JWT detector (score 40)
        # 3. Specific regex assignments e.g. api-key-assignment, token-assignment (score 30)
        # 4. Generic high entropy secret (score 25)
        # 5. Generic credential / generic secret regex (score 20)
        # 6. Other / fallback (score 10)
        def specificity_key(item: Tuple[DetectionCandidate, ScoredResult]) -> int:
            c, _ = item
            r_id = c.rule_id or ""
            from envguard.detectors.regex_detector import PROVIDER_PREFIX_RULES
            if c.source == "regex" and r_id in PROVIDER_PREFIX_RULES:
                return 50
            if c.source == "jwt":
                return 40
            if c.source == "regex" and r_id in ("db-password-assignment", "secret-key-assignment"):
                return 35
            if c.source == "regex" and not r_id.startswith("generic-"):
                return 30
            if c.rule_id == "generic-high-entropy-secret":
                return 25
            if c.source == "regex":
                return 20
            return 10


        cluster.sort(key=specificity_key, reverse=True)
        primary_cand, primary_scored = cluster[0]

        # Check inline suppression on primary rule ID
        if suppression_mgr and suppression_mgr.is_suppressed(line_number, primary_cand.rule_id or ""):
            if stats is not None:
                stats["suppressed_count"] = stats.get("suppressed_count", 0) + 1
            continue

        # Merge all unique signals from all items in the cluster
        merged_signals: List[str] = []
        for _, s in cluster:
            for sig in s.signals:
                if sig not in merged_signals:
                    merged_signals.append(sig)

        # Adopt highest severity in the cluster
        severities = [s.severity for _, s in cluster if s.severity != "IGNORE"]
        best_sev = primary_scored.severity
        for sev in severities:
            if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(best_sev, 0):
                best_sev = sev

        entropy_val = next((c.entropy_value for c, _ in cluster if c.entropy_value is not None), None)
        provider_val = next((c.provider for c, _ in cluster if c.provider), None)

        fp = primary_cand.fingerprint or compute_fingerprint(primary_cand.rule_id or "generic-secret", actual_file_path, primary_cand.value)
        masked = primary_cand.masked_value or mask_secret(primary_cand.value)

        findings.append(
            ScanFinding(
                rule_id=primary_cand.rule_id or "generic-secret",
                rule_name=primary_cand.rule_name or "Detected Secret",
                severity=best_sev,
                file_path=actual_file_path,
                line_number=line_number,
                raw_value=primary_cand.value,
                masked_value=masked,
                fingerprint=fp,
                line_snippet=line_snippet,
                detection_signals=merged_signals,
                entropy=entropy_val,
                provider=provider_val,
            )
        )

    return findings


def scan_lines(
    lines: List[str],
    file_path_str: str,
    patterns: List[Pattern],
    suppression_mgr: Optional[SuppressionManager] = None,
    advanced_config: Optional[AdvancedDetectionConfig] = None,
    stats: Optional[Dict[str, int]] = None,
    full_text: Optional[str] = None,
) -> List[ScanFinding]:
    """Scan list of text lines orchestrating regex, JWT, entropy, and scoring."""
    findings: List[ScanFinding] = []
    cfg = advanced_config or AdvancedDetectionConfig()

    for line_idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        candidates: List[DetectionCandidate] = []

        # 1. Regex detector
        regex_cands = detect_regex_candidates(
            line=line,
            line_number=line_idx,
            file_path=file_path_str,
            patterns=patterns,
            full_text=full_text,
        )
        candidates.extend(regex_cands)

        # 2. JWT detector
        if cfg.jwt_enabled:
            jwt_cands = detect_jwt_candidates(
                line=line,
                line_number=line_idx,
                file_path=file_path_str,
                config=cfg,
            )
            candidates.extend(jwt_cands)

        # 3. Entropy detector
        if cfg.entropy_enabled:
            entropy_cands = detect_entropy_candidates(
                line=line,
                line_number=line_idx,
                file_path=file_path_str,
                config=cfg,
            )
            candidates.extend(entropy_cands)

        if not candidates:
            continue

        # 4. Score candidates
        scored_candidates: List[Tuple[DetectionCandidate, ScoredResult]] = []
        for cand in candidates:
            scored = score_candidate(cand)
            if scored.severity != "IGNORE":
                scored_candidates.append((cand, scored))

        if not scored_candidates:
            continue

        # 5. Deduplicate and merge into findings
        merged = deduplicate_and_merge_candidates(
            scored_candidates=scored_candidates,
            line_snippet=stripped,
            line_number=line_idx,
            file_path=file_path_str,
            suppression_mgr=suppression_mgr,
            stats=stats,
        )
        findings.extend(merged)

    return findings


def scan_text(
    text: str,
    file_path_str: str,
    patterns: List[Pattern],
    suppression_mgr: Optional[SuppressionManager] = None,
    stats: Optional[Dict[str, int]] = None,
    advanced_config: Optional[AdvancedDetectionConfig] = None,
) -> List[ScanFinding]:
    """Scan string content line by line using multi-signal detection engine."""
    lines = text.splitlines()
    if suppression_mgr is None:
        suppression_mgr = parse_suppressions_from_lines(lines)

    return scan_lines(
        lines=lines,
        file_path_str=file_path_str,
        patterns=patterns,
        suppression_mgr=suppression_mgr,
        advanced_config=advanced_config,
        stats=stats,
        full_text=text,
    )


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
    stats: Optional[Dict[str, int]] = None,
    advanced_config: Optional[AdvancedDetectionConfig] = None,
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

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        suppression_mgr = parse_suppressions_from_lines(lines)
        findings = scan_lines(
            lines=lines,
            file_path_str=rel_path_str,
            patterns=patterns,
            suppression_mgr=suppression_mgr,
            advanced_config=advanced_config,
            stats=stats,
            full_text="".join(lines),
        )
        return findings, None
    except Exception as e:
        return [], f"read error: {e}"


def scan_files(
    files: List[Path],
    base_dir: Path,
    patterns: Optional[List[Pattern]] = None,
    respect_gitignore: bool = True,
    exclude_patterns: Optional[List[str]] = None,
    max_file_size_bytes: int = DEFAULT_MAX_BYTES,
    verbose_log: Optional[List[str]] = None,
    stats: Optional[Dict[str, int]] = None,
    advanced_config: Optional[AdvancedDetectionConfig] = None,
) -> List[ScanFinding]:
    """Scan an explicit list of file paths against secret patterns."""
    if patterns is None:
        patterns = load_default_patterns()

    if stats is not None:
        stats.setdefault("files_scanned", 0)
        stats.setdefault("files_skipped", 0)
        stats.setdefault("suppressed_count", 0)
        stats.setdefault("ignored_by_envguardignore", 0)
        stats.setdefault("ignored_by_gitignore", 0)

    gitignore_spec = load_root_gitignore(base_dir) if respect_gitignore else None
    envguardignore_spec = load_envguardignore(base_dir)
    config_exclude_spec = compile_exclude_spec(exclude_patterns or [])

    all_findings: List[ScanFinding] = []

    for item in sorted(files):
        if not item.is_file():
            continue

        try:
            rel_path = str(item.relative_to(base_dir)).replace("\\", "/")
        except ValueError:
            rel_path = str(item).replace("\\", "/")

        ignored, reason = is_path_ignored(
            rel_path=rel_path,
            gitignore_spec=gitignore_spec,
            envguardignore_spec=envguardignore_spec,
            config_exclude_spec=config_exclude_spec,
            is_dir=False,
        )

        if ignored:
            if stats is not None:
                if reason == "envguardignore":
                    stats["ignored_by_envguardignore"] += 1
                elif reason == "gitignore":
                    stats["ignored_by_gitignore"] += 1
            if verbose_log is not None:
                verbose_log.append(f"Skipped {rel_path} ({reason})")
            continue

        findings, skip_reason = scan_file_streaming(
            file_path=item,
            rel_path_str=rel_path,
            patterns=patterns,
            max_file_size_bytes=max_file_size_bytes,
            stats=stats,
            advanced_config=advanced_config,
        )

        if skip_reason:
            if stats is not None:
                stats["files_skipped"] += 1
            if verbose_log is not None:
                verbose_log.append(f"Skipped {rel_path} ({skip_reason})")
        else:
            if stats is not None:
                stats["files_scanned"] += 1
            all_findings.extend(findings)

    return all_findings


def scan_directory(
    directory: Path,
    patterns: Optional[List[Pattern]] = None,
    respect_gitignore: bool = True,
    exclude_patterns: Optional[List[str]] = None,
    max_file_size_bytes: int = DEFAULT_MAX_BYTES,
    verbose_log: Optional[List[str]] = None,
    stats: Optional[Dict[str, int]] = None,
    advanced_config: Optional[AdvancedDetectionConfig] = None,
    changed_only: bool = False,
    base_ref: Optional[str] = None,
) -> List[ScanFinding]:
    """Scan current working directory recursively with streaming, .envguardignore, and suppression.

    Supports changed_only=True to scan only files modified relative to base_ref.
    """
    if patterns is None:
        patterns = load_default_patterns()

    if changed_only:
        from envguard.exceptions import GitError
        from envguard.git_utils import get_changed_files, get_default_base_branch, is_git_repository

        if not is_git_repository(directory):
            raise GitError("Cannot scan changed files: current directory is not a Git repository.")

        ref = base_ref or get_default_base_branch(directory) or "HEAD~1"
        changed_files = get_changed_files(base=ref, head="HEAD", repo_path=directory)
        return scan_files(
            files=changed_files,
            base_dir=directory,
            patterns=patterns,
            respect_gitignore=respect_gitignore,
            exclude_patterns=exclude_patterns,
            max_file_size_bytes=max_file_size_bytes,
            verbose_log=verbose_log,
            stats=stats,
            advanced_config=advanced_config,
        )

    if stats is not None:
        stats.setdefault("files_scanned", 0)
        stats.setdefault("files_skipped", 0)
        stats.setdefault("suppressed_count", 0)
        stats.setdefault("ignored_by_envguardignore", 0)
        stats.setdefault("ignored_by_gitignore", 0)

    if directory.is_file():
        findings, skip_reason = scan_file_streaming(
            file_path=directory,
            rel_path_str=directory.name,
            patterns=patterns,
            max_file_size_bytes=max_file_size_bytes,
            stats=stats,
            advanced_config=advanced_config,
        )
        if stats is not None:
            if skip_reason:
                stats["files_skipped"] += 1
            else:
                stats["files_scanned"] += 1
        return findings

    gitignore_spec = load_root_gitignore(directory) if respect_gitignore else None
    envguardignore_spec = load_envguardignore(directory)
    config_exclude_spec = compile_exclude_spec(exclude_patterns or [])

    all_findings: List[ScanFinding] = []

    # Traverse directory while pruning ignored subdirectories (node_modules, .git, etc.)
    for root, dirs, files in os.walk(directory):
        rel_root = str(Path(root).relative_to(directory)).replace("\\", "/")

        # Prune ignored subdirectories
        kept_dirs = []
        for d in sorted(dirs):
            dir_rel = f"{rel_root}/{d}" if rel_root != "." else d
            ignored, reason = is_path_ignored(
                rel_path=dir_rel,
                gitignore_spec=gitignore_spec,
                envguardignore_spec=envguardignore_spec,
                config_exclude_spec=config_exclude_spec,
                is_dir=True,
            )
            if ignored:
                if stats is not None:
                    if reason == "envguardignore":
                        stats["ignored_by_envguardignore"] += 1
                    elif reason == "gitignore":
                        stats["ignored_by_gitignore"] += 1
                if verbose_log is not None:
                    verbose_log.append(f"Skipped directory {dir_rel}/ ({reason})")
            else:
                kept_dirs.append(d)
        dirs[:] = kept_dirs

        for filename in sorted(files):
            item = Path(root) / filename
            rel_path = f"{rel_root}/{filename}" if rel_root != "." else filename

            ignored, reason = is_path_ignored(
                rel_path=rel_path,
                gitignore_spec=gitignore_spec,
                envguardignore_spec=envguardignore_spec,
                config_exclude_spec=config_exclude_spec,
                is_dir=False,
            )

            if ignored:
                if stats is not None:
                    if reason == "envguardignore":
                        stats["ignored_by_envguardignore"] += 1
                    elif reason == "gitignore":
                        stats["ignored_by_gitignore"] += 1
                if verbose_log is not None:
                    verbose_log.append(f"Skipped {rel_path} ({reason})")
                continue

            findings, skip_reason = scan_file_streaming(
                file_path=item,
                rel_path_str=rel_path,
                patterns=patterns,
                max_file_size_bytes=max_file_size_bytes,
                stats=stats,
                advanced_config=advanced_config,
            )

            if skip_reason:
                if stats is not None:
                    stats["files_skipped"] += 1
                if verbose_log is not None:
                    verbose_log.append(f"Skipped {rel_path} ({skip_reason})")
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
    stats: Optional[Dict[str, int]] = None,
    advanced_config: Optional[AdvancedDetectionConfig] = None,
) -> List[ScanFinding]:
    """Scan staged files directly from Git index using git show :path."""
    if patterns is None:
        patterns = load_default_patterns()

    target_repo = repo_path or Path.cwd()
    envguardignore_spec = load_envguardignore(target_repo)
    config_exclude_spec = compile_exclude_spec(exclude_patterns or [])
    staged_files = get_staged_files(repo_path)
    all_findings: List[ScanFinding] = []

    for rel_path in staged_files:
        ignored, reason = is_path_ignored(
            rel_path=rel_path,
            gitignore_spec=None,
            envguardignore_spec=envguardignore_spec,
            config_exclude_spec=config_exclude_spec,
            is_dir=False,
        )
        if ignored:
            if stats is not None and reason == "envguardignore":
                stats["ignored_by_envguardignore"] = stats.get("ignored_by_envguardignore", 0) + 1
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
            findings = scan_text(
                text=content,
                file_path_str=rel_path,
                patterns=patterns,
                stats=stats,
                advanced_config=advanced_config,
            )
            all_findings.extend(findings)
        except Exception:
            # Handle decoding or git errors gracefully for individual files
            continue

    return all_findings
