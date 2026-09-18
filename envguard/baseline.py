"""Baseline management for EnvGuard (.envguard-baseline.json)."""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from envguard.exceptions import BaselineError
from envguard.scanner import ScanFinding

DEFAULT_BASELINE_FILENAME = ".envguard-baseline.json"
BASELINE_SCHEMA_VERSION = 1


def load_baseline(baseline_path: Path) -> Set[str]:
    """Load baseline file and return a set of known fingerprints.

    Returns an empty set if the baseline file does not exist.
    """
    if not baseline_path.is_file():
        return set()

    try:
        content = baseline_path.read_text(encoding="utf-8")
        data = json.loads(content)
    except Exception as e:
        raise BaselineError(f"Failed to read baseline file '{baseline_path.name}': {e}")

    if not isinstance(data, dict):
        raise BaselineError(f"Invalid baseline file format in '{baseline_path.name}' (expected JSON object).")

    version = data.get("version", 1)
    if version != BASELINE_SCHEMA_VERSION:
        raise BaselineError(f"Unsupported baseline version {version} (supported: {BASELINE_SCHEMA_VERSION})")

    fingerprints: Set[str] = set()
    for item in data.get("findings", []):
        fp = item.get("fingerprint")
        if fp:
            fingerprints.add(fp)

    return fingerprints


def inspect_baseline(baseline_path: Path) -> Tuple[bool, int, Optional[str]]:
    """Inspect baseline file validity and fingerprint count.

    Returns:
        (exists, count, error_message)
        - If file does not exist: (False, 0, None)
        - If valid: (True, count, None)
        - If invalid: (True, 0, error_message)
    """
    if not baseline_path.is_file():
        return False, 0, None

    try:
        fingerprints = load_baseline(baseline_path)
        return True, len(fingerprints), None
    except Exception as e:
        return True, 0, str(e)


def filter_baseline_findings(
    findings: List[ScanFinding],
    baseline_fingerprints: Set[str],
) -> Tuple[List[ScanFinding], List[ScanFinding]]:
    """Separate active findings from known baseline findings.

    Supports both canonical fingerprints and legacy path-based fingerprints.
    Returns (new_findings, baseline_suppressed_findings).
    """
    if not baseline_fingerprints:
        return findings, []

    new_findings: List[ScanFinding] = []
    suppressed: List[ScanFinding] = []

    for f in findings:
        matched = False
        if f.fingerprint in baseline_fingerprints:
            matched = True
        else:
            # Check legacy fingerprint for primary location
            if hasattr(f, "rule_id") and hasattr(f, "file_path") and hasattr(f, "raw_value"):
                from envguard.scanner import compute_legacy_fingerprint
                legacy_fp = compute_legacy_fingerprint(f.rule_id, f.file_path, f.raw_value)
                if legacy_fp in baseline_fingerprints:
                    matched = True

            # If not matched yet, check secondary occurrences against baseline fingerprints
            if not matched:
                for occ in getattr(f, "occurrences", []):
                    occ_file = occ.get("file_path")
                    if occ_file:
                        from envguard.scanner import compute_legacy_fingerprint
                        occ_legacy_fp = compute_legacy_fingerprint(f.rule_id, occ_file, f.raw_value)
                        if occ_legacy_fp in baseline_fingerprints:
                            matched = True
                            break

        if matched:
            suppressed.append(f)
        else:
            new_findings.append(f)

    return new_findings, suppressed


def create_baseline(
    findings: List[ScanFinding],
    output_path: Path,
    overwrite: bool = False,
) -> int:
    """Create a new .envguard-baseline.json from a list of findings.

    Never stores raw secret values.
    Returns the number of findings captured.
    """
    if output_path.exists() and not overwrite:
        raise BaselineError(
            f"Baseline file '{output_path.name}' already exists. Use --overwrite to replace it."
        )

    # Sort findings for deterministic output
    sorted_findings = sorted(
        findings,
        key=lambda x: (x.file_path, x.line_number, x.rule_id),
    )

    baseline_entries: List[Dict] = []
    seen_fingerprints: Set[str] = set()

    for f in sorted_findings:
        if f.fingerprint in seen_fingerprints:
            continue
        seen_fingerprints.add(f.fingerprint)
        entry: Dict[str, Any] = {
            "fingerprint": f.fingerprint,
            "rule_id": f.rule_id,
            "file": f.file_path.replace("\\", "/"),
            "line": f.line_number,
        }
        if getattr(f, "occurrences", None):
            entry["occurrences"] = [
                {
                    "file": occ.get("file_path", "").replace("\\", "/"),
                    "line": occ.get("line_number"),
                }
                for occ in f.occurrences
            ]
        baseline_entries.append(entry)

    payload = {
        "version": BASELINE_SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(baseline_entries),
        "findings": baseline_entries,
    }

    try:
        output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    except Exception as e:
        raise BaselineError(f"Failed to write baseline file '{output_path.name}': {e}")

    return len(baseline_entries)
