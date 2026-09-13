"""GitHub Actions workflow integration for EnvGuard v0.5.0.

Provides native GitHub Actions workflow annotations (::error::, ::warning::, ::notice::)
and rich Markdown step summaries (GITHUB_STEP_SUMMARY).
Guarantees 100% privacy: plain-text secrets are strictly never emitted to logs or summaries.
"""

import os
from pathlib import Path
import sys
from typing import List, Optional, TextIO

from envguard.ci import CIEnvironment
from envguard.scanner import ScanFinding

ANNOTATION_SEVERITY_MAP = {
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "notice",
}


def write_github_annotations(
    findings: List[ScanFinding],
    stream: Optional[TextIO] = None,
    force: bool = False,
) -> None:
    """Emit GitHub Actions workflow annotations to stdout or stream.

    Format:
    ::error file=config.py,line=15,title=EnvGuard HIGH::Potential secret detected (rule-id)

    Plaintext secrets are NEVER emitted in annotations.
    """
    if not force and os.environ.get("GITHUB_ACTIONS", "").lower() != "true":
        return

    out = stream if stream is not None else sys.stdout

    for f in findings:
        level = ANNOTATION_SEVERITY_MAP.get(f.severity.upper(), "warning")
        normalized_path = f.file_path.replace("\\", "/")
        line = max(1, f.line_number)
        title = f"EnvGuard {f.severity.upper()}"
        safe_msg = f"Potential secret detected matching rule '{f.rule_id}' ({f.rule_name})"

        annotation = f"::{level} file={normalized_path},line={line},title={title}::{safe_msg}\n"
        out.write(annotation)
    out.flush()


def generate_job_summary_markdown(
    findings: List[ScanFinding],
    files_scanned: int,
    baseline_suppressed: int,
    block_on: List[str],
    ci_env: Optional[CIEnvironment] = None,
) -> str:
    """Generate Markdown text for GitHub Actions step summary."""
    blocking = [f for f in findings if f.is_blocking_for(block_on)]
    is_blocked = len(blocking) > 0
    status_icon = "❌" if is_blocked else "✅"
    status_text = "BLOCKED" if is_blocked else "PASSED"

    high = sum(1 for f in findings if f.severity == "HIGH")
    medium = sum(1 for f in findings if f.severity == "MEDIUM")
    low = sum(1 for f in findings if f.severity == "LOW")

    lines: List[str] = [
        "## EnvGuard Security Scan",
        "",
        f"**Result Status:** {status_icon} **{status_text}**",
        "",
    ]

    # CI Pipeline metadata
    meta_parts: List[str] = []
    if ci_env and ci_env.repository:
        meta_parts.append(f"**Repository:** `{ci_env.repository}`")
    if ci_env and ci_env.branch:
        meta_parts.append(f"**Branch / Ref:** `{ci_env.branch}`")
    if ci_env and ci_env.commit_sha:
        meta_parts.append(f"**Commit:** `{ci_env.commit_sha[:8]}`")
    if ci_env and ci_env.pull_request:
        meta_parts.append(f"**Pull Request:** `#{ci_env.pull_request}`")

    if meta_parts:
        lines.append(" | ".join(meta_parts))
        lines.append("")

    # Summary table
    lines.extend(
        [
            "### Scan Statistics",
            "",
            "| Metric | Count |",
            "|---|:---:|",
            f"| Files Scanned | {files_scanned} |",
            f"| Actionable Findings | {len(findings)} |",
            f"| High Severity | {high} |",
            f"| Medium Severity | {medium} |",
            f"| Low Severity | {low} |",
            f"| Historical Baseline Suppressed | {baseline_suppressed} |",
            "",
        ]
    )

    # Findings table
    if findings:
        lines.extend(
            [
                "### Detected Secrets",
                "",
                "| Severity | Rule ID | File | Line | Masked Value |",
                "|:---:|---|---|:---:|---|",
            ]
        )
        for f in findings:
            sev_badge = "🔴 HIGH" if f.severity == "HIGH" else ("🟡 MEDIUM" if f.severity == "MEDIUM" else "🔵 LOW")
            norm_file = f.file_path.replace("\\", "/")
            masked = f.masked_value or "••••••••"
            lines.append(f"| {sev_badge} | `{f.rule_id}` | `{norm_file}` | {f.line_number} | `{masked}` |")
        lines.append("")
    else:
        lines.extend(
            [
                "### Findings",
                "",
                "> 🎉 **No active secrets detected in this scan.**",
                "",
            ]
        )

    lines.extend(
        [
            "---",
            "*Report generated locally by [EnvGuard](https://github.com/neil-data/envGUARD) — Zero-telemetry developer security.*",
            "",
        ]
    )

    return "\n".join(lines)


def write_github_job_summary(
    findings: List[ScanFinding],
    files_scanned: int,
    baseline_suppressed: int,
    block_on: List[str],
    ci_env: Optional[CIEnvironment] = None,
    summary_file: Optional[Path] = None,
    force: bool = False,
) -> bool:
    """Append Markdown summary to GITHUB_STEP_SUMMARY file.

    Returns True if successfully written, False otherwise.
    """
    if not force and os.environ.get("GITHUB_ACTIONS", "").lower() != "true":
        return False

    target_file = summary_file
    if target_file is None:
        env_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if env_path:
            target_file = Path(env_path)

    if not target_file:
        return False

    try:
        content = generate_job_summary_markdown(
            findings=findings,
            files_scanned=files_scanned,
            baseline_suppressed=baseline_suppressed,
            block_on=block_on,
            ci_env=ci_env,
        )
        # Ensure parent exists
        target_file.parent.mkdir(parents=True, exist_ok=True)
        with open(target_file, "a", encoding="utf-8") as f:
            f.write(content + "\n")
        return True
    except Exception:
        return False
