"""Historical Trend Engine for EnvGuard v0.9.0.

Analyzes current scan findings against baseline snapshots (.envguard-baseline.json)
to track:
- New findings (introduced drift)
- Resolved findings (remediated debt)
- Persistent findings (suppressed legacy debt)
- Net debt delta and remediation velocity percentage
"""

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Dict, List, Optional, Set

from envguard.baseline import load_baseline
from envguard.scanner import ScanFinding


@dataclass
class BaselineTrendReport:
    baseline_exists: bool
    baseline_path: Optional[str]
    baseline_count: int
    current_count: int
    new_findings: List[ScanFinding] = field(default_factory=list)
    resolved_count: int = 0
    persistent_findings: List[ScanFinding] = field(default_factory=list)
    remediation_rate_pct: float = 0.0
    trend_direction: str = "NEUTRAL"  # IMPROVING, DEGRADING, NEUTRAL, STABLE


def compute_baseline_trend(
    findings: List[ScanFinding],
    baseline_path: Optional[Path] = None,
) -> BaselineTrendReport:
    """Compare active scan findings against a baseline snapshot.

    Calculates new drift, resolved secrets, and persistent debt.
    """
    if baseline_path is None or not baseline_path.is_file():
        return BaselineTrendReport(
            baseline_exists=False,
            baseline_path=str(baseline_path) if baseline_path else None,
            baseline_count=0,
            current_count=len(findings),
            new_findings=findings,
            resolved_count=0,
            persistent_findings=[],
            remediation_rate_pct=0.0,
            trend_direction="NEUTRAL" if len(findings) == 0 else "DEGRADING",
        )

    try:
        baseline_fingerprints = load_baseline(baseline_path)
    except Exception:
        baseline_fingerprints = set()

    current_fingerprints = {f.fingerprint for f in findings}
    baseline_count = len(baseline_fingerprints)
    current_count = len(findings)

    new_findings: List[ScanFinding] = []
    persistent_findings: List[ScanFinding] = []
    matched_baseline_fps: Set[str] = set()

    for f in findings:
        matched = False
        if f.fingerprint in baseline_fingerprints:
            matched = True
            matched_baseline_fps.add(f.fingerprint)

        # Check legacy fingerprint (canonical vs legacy path-based SHA256)
        if hasattr(f, "rule_id") and hasattr(f, "file_path") and hasattr(f, "raw_value"):
            from envguard.scanner import compute_legacy_fingerprint
            legacy_fp = compute_legacy_fingerprint(f.rule_id, f.file_path, f.raw_value)
            if legacy_fp in baseline_fingerprints:
                matched = True
                matched_baseline_fps.add(legacy_fp)

        # Check secondary occurrences
        for occ in getattr(f, "occurrences", []):
            occ_file = occ.get("file_path")
            if occ_file and hasattr(f, "rule_id") and hasattr(f, "raw_value"):
                from envguard.scanner import compute_legacy_fingerprint
                occ_legacy_fp = compute_legacy_fingerprint(f.rule_id, occ_file, f.raw_value)
                if occ_legacy_fp in baseline_fingerprints:
                    matched = True
                    matched_baseline_fps.add(occ_legacy_fp)

        if matched:
            persistent_findings.append(f)
        else:
            new_findings.append(f)

    # Resolved count: ONLY baseline secrets genuinely absent from the current scan
    resolved_count = len(baseline_fingerprints - matched_baseline_fps)

    if baseline_count > 0:
        remediation_rate = round((resolved_count / baseline_count) * 100.0, 1)
    else:
        remediation_rate = 0.0

    if len(new_findings) > 0 and len(new_findings) >= resolved_count:
        trend_direction = "DEGRADING"
    elif resolved_count > len(new_findings):
        trend_direction = "IMPROVING"
    elif current_count == 0 and baseline_count == 0:
        trend_direction = "STABLE"
    elif len(new_findings) == 0 and resolved_count == 0:
        trend_direction = "STABLE"
    else:
        trend_direction = "NEUTRAL"

    return BaselineTrendReport(
        baseline_exists=True,
        baseline_path=str(baseline_path),
        baseline_count=baseline_count,
        current_count=current_count,
        new_findings=new_findings,
        resolved_count=resolved_count,
        persistent_findings=persistent_findings,
        remediation_rate_pct=remediation_rate,
        trend_direction=trend_direction,
    )
