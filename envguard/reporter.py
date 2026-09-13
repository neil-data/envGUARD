"""Reporter and formatting module for EnvGuard v0.2.5.

Supports both human-friendly Rich terminal UI and machine-readable JSON formats.
Follows consistent severity presentation and layout standards across all commands.
"""

import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from envguard import __version__
from envguard.diagnostics import DiagnosticReport
from envguard.env_diff import EnvDiffResult
from envguard.initializer import InitResult
from envguard.patterns import Pattern
from envguard.scanner import ScanFinding
from envguard.theme import (
    COLOR_ERROR,
    COLOR_HIGH,
    COLOR_INFO,
    COLOR_LOW,
    COLOR_MEDIUM,
    COLOR_SUCCESS,
    COLOR_WARNING,
    SYMBOL_ERROR,
    SYMBOL_INFO,
    SYMBOL_SUCCESS,
    SYMBOL_WARNING,
    console,
    create_error_panel,
    create_panel,
    create_success_panel,
    create_summary_panel,
    format_severity,
)

JSON_SCHEMA_VERSION = 1


def print_json(data: Dict[str, Any]) -> None:
    """Print pure JSON to stdout with 2-space indentation."""
    print(json.dumps(data, indent=2))


def render_scan_json(
    findings: List[ScanFinding],
    command: str = "scan",
    status: Optional[str] = None,
    suppressed_count: int = 0,
) -> None:
    """Output scan findings in structured JSON format."""
    high = sum(1 for f in findings if f.severity == "HIGH")
    medium = sum(1 for f in findings if f.severity == "MEDIUM")
    low = sum(1 for f in findings if f.severity == "LOW")

    if status is None:
        status = "failed" if (high > 0 or medium > 0) else "passed"

    data = {
        "schema_version": JSON_SCHEMA_VERSION,
        "envguard_version": __version__,
        "command": command,
        "status": status,
        "summary": {
            "high": high,
            "medium": medium,
            "low": low,
            "total": len(findings),
            "baseline_suppressed": suppressed_count,
        },
        "findings": [
            {
                **{
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "severity": f.severity,
                    "file": f.file_path.replace("\\", "/"),
                    "line": f.line_number,
                    "masked_value": f.masked_value,
                    "fingerprint": f.fingerprint,
                },
                **({"entropy": f.entropy} if getattr(f, "entropy", None) is not None else {}),
                **({"provider": f.provider} if getattr(f, "provider", None) else {}),
                **({"detection_signals": f.detection_signals} if getattr(f, "detection_signals", None) else {}),
            }
            for f in findings
        ],
    }
    print_json(data)


def render_check_json(
    blocking_findings: Optional[List[ScanFinding]] = None,
    low_findings: Optional[List[ScanFinding]] = None,
    no_staged: bool = False,
    error: Optional[str] = None,
) -> None:
    """Output git check result in structured JSON format."""
    if error:
        data = {
            "schema_version": JSON_SCHEMA_VERSION,
            "envguard_version": __version__,
            "command": "check",
            "status": "error",
            "error": error,
        }
        print_json(data)
        return

    blocking = blocking_findings or []
    low = low_findings or []
    all_findings = blocking + low
    status = "failed" if blocking else "passed"
    if no_staged:
        status = "passed"

    high = sum(1 for f in all_findings if f.severity == "HIGH")
    medium = sum(1 for f in all_findings if f.severity == "MEDIUM")
    low = sum(1 for f in all_findings if f.severity == "LOW")

    data = {
        "schema_version": JSON_SCHEMA_VERSION,
        "envguard_version": __version__,
        "command": "check",
        "status": status,
        "staged_files_present": not no_staged,
        "commit_blocked": bool(blocking_findings),
        "summary": {
            "high": high,
            "medium": medium,
            "low": low,
            "total": len(all_findings),
        },
        "findings": [
            {
                **{
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "severity": f.severity,
                    "file": f.file_path.replace("\\", "/"),
                    "line": f.line_number,
                    "masked_value": f.masked_value,
                    "fingerprint": f.fingerprint,
                },
                **({"entropy": f.entropy} if getattr(f, "entropy", None) is not None else {}),
                **({"provider": f.provider} if getattr(f, "provider", None) else {}),
                **({"detection_signals": f.detection_signals} if getattr(f, "detection_signals", None) else {}),
            }
            for f in all_findings
        ],
    }
    print_json(data)


def render_diff_json(
    diff_result: Optional[EnvDiffResult],
    error: Optional[str] = None,
) -> None:
    """Output environment diff in structured JSON format."""
    if error:
        data = {
            "schema_version": JSON_SCHEMA_VERSION,
            "envguard_version": __version__,
            "command": "diff",
            "status": "error",
            "error": error,
        }
    else:
        status = "failed" if (diff_result and diff_result.has_drift) else "passed"
        data = {
            "schema_version": JSON_SCHEMA_VERSION,
            "envguard_version": __version__,
            "command": "diff",
            "status": status,
            "has_drift": diff_result.has_drift if diff_result else False,
            "missing_from_example": diff_result.missing_from_example if diff_result else [],
            "extra_in_example": diff_result.extra_in_example if diff_result else [],
        }
    print_json(data)


def render_status_json(
    is_git: bool,
    env_tracked: bool,
    findings: List[ScanFinding],
    diff_result: Optional[EnvDiffResult],
    hook_installed: bool,
    overall_status: str,
) -> None:
    """Output status dashboard in structured JSON format."""
    high = sum(1 for f in findings if f.severity == "HIGH")
    medium = sum(1 for f in findings if f.severity == "MEDIUM")
    low = sum(1 for f in findings if f.severity == "LOW")

    data = {
        "schema_version": JSON_SCHEMA_VERSION,
        "envguard_version": __version__,
        "command": "status",
        "status": "passed" if overall_status == "SECURE" else "attention_required",
        "overall_status": overall_status,
        "checks": {
            "is_git_repository": is_git,
            "env_file_tracked": env_tracked,
            "secrets_detected": {
                "high": high,
                "medium": medium,
                "low": low,
                "total": len(findings),
            },
            "environment_drift": {
                "has_drift": diff_result.has_drift if diff_result else False,
                "missing_from_example": diff_result.missing_from_example if diff_result else [],
                "extra_in_example": diff_result.extra_in_example if diff_result else [],
            },
            "pre_commit_hook_installed": hook_installed,
        },
    }
    print_json(data)


def render_init_json(result: InitResult) -> None:
    """Output initialization result in structured JSON format."""
    data = {
        "schema_version": JSON_SCHEMA_VERSION,
        "envguard_version": __version__,
        "command": "init",
        "status": "passed",
        "files": {
            "config": {
                "path": result.config_path.replace("\\", "/"),
                "created": result.config_created,
                "already_existed": result.config_existed,
            },
            "ignore": {
                "path": result.ignore_path.replace("\\", "/"),
                "created": result.ignore_created,
                "already_existed": result.ignore_existed,
            },
        },
    }
    print_json(data)


def render_doctor_json(report: DiagnosticReport) -> None:
    """Output doctor diagnostic report in structured JSON format."""
    status_map = {"PASS": "passed", "WARNING": "warning", "ERROR": "failed"}
    data = {
        "schema_version": JSON_SCHEMA_VERSION,
        "envguard_version": __version__,
        "command": "doctor",
        "status": status_map.get(report.overall_status, "warning"),
        "summary": {
            "passed": report.passed_count,
            "warnings": report.warning_count,
            "errors": report.error_count,
            "total": len(report.checks),
        },
        "checks": [
            {
                "name": c.name,
                "status": c.status,
                "details": c.details,
                "recommendation": c.recommendation,
            }
            for c in report.checks
        ],
    }
    print_json(data)


def render_explain_json(pattern: Pattern) -> None:
    """Output rule explanation in structured JSON format."""
    data = {
        "schema_version": JSON_SCHEMA_VERSION,
        "envguard_version": __version__,
        "command": "explain",
        "status": "passed",
        "rule": {
            "id": pattern.id,
            "name": pattern.name,
            "severity": pattern.severity,
            "enabled": pattern.enabled,
            "description": pattern.description,
            "detects": getattr(pattern, "detects", pattern.description),
            "why_it_matters": getattr(pattern, "why_it_matters", ""),
            "remediation": getattr(pattern, "remediation", ""),
        },
    }
    print_json(data)


def render_rules_json(patterns: List[Pattern]) -> None:
    """Output rules list in structured JSON format."""
    data = {
        "schema_version": JSON_SCHEMA_VERSION,
        "envguard_version": __version__,
        "command": "rules",
        "status": "passed",
        "total_rules": len(patterns),
        "rules": [
            {
                "id": p.id,
                "name": p.name,
                "severity": p.severity,
                "enabled": p.enabled,
                "description": p.description,
                "detects": getattr(p, "detects", p.description),
                "why_it_matters": getattr(p, "why_it_matters", ""),
                "remediation": getattr(p, "remediation", ""),
            }
            for p in patterns
        ],
    }
    print_json(data)


# --------------------------------------------------------------------------
# Terminal Presentation Functions (Rich-Powered UI)
# --------------------------------------------------------------------------

SIGNAL_LABELS = {
    "high_entropy": "High entropy",
    "credential_variable_name": "Credential variable",
    "token_like_length": "Token-like length",
    "non_placeholder_value": "Non-placeholder",
    "jwt_structure": "JWT structure",
    "valid_jwt_header": "Valid JWT header",
    "valid_base64url_segments": "Base64URL encoded",
    "known_pattern_match": "Pattern match",
    "provider_prefix": "Provider prefix",
    "private_key_header": "Private key header",
}


def format_signals(finding: ScanFinding) -> str:
    """Format detection signals for table display."""
    signals = getattr(finding, "detection_signals", None) or []
    if not signals:
        return "-"
    formatted = []
    for s in signals:
        if s == "high_entropy" and getattr(finding, "entropy", None) is not None:
            formatted.append(f"Entropy ({finding.entropy:.2f})")
        else:
            formatted.append(SIGNAL_LABELS.get(s, s.replace("_", " ").capitalize()))
    return ", ".join(formatted[:2])


def print_scan_findings(
    findings: List[ScanFinding],
    title: str = "Scan Report",
    stats: Optional[Dict[str, Any]] = None,
) -> None:
    """Display scan findings in a Rich-styled table with summary."""
    if not findings:
        console.print()
        console.print(create_success_panel("SCAN PASSED", "No secrets were detected in the scanned files."))
        console.print()
        return

    # 1. Summary banner
    if stats:
        console.print()
        console.print(
            create_summary_panel(
                files_scanned=stats.get("files_scanned", 0),
                files_skipped=stats.get("files_skipped", 0),
                findings_count=len(findings),
            )
        )

    # 2. Findings Table
    table = Table(
        title="[bold]Detected Secrets[/bold]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        expand=False,
    )
    has_signals = any(bool(getattr(f, "detection_signals", None)) for f in findings)
    table.add_column("Severity", justify="center", style="bold")
    table.add_column("Rule ID", style="bold")
    table.add_column("File")
    table.add_column("Line", justify="right")
    table.add_column("Masked Value", style="cyan")
    if has_signals:
        table.add_column("Signals", style="magenta")

    for f in findings:
        row = [
            format_severity(f.severity),
            f.rule_id,
            f.file_path,
            str(f.line_number),
            f.masked_value,
        ]
        if has_signals:
            row.append(format_signals(f))
        table.add_row(*row)

    console.print()
    console.print(table)

    # 3. Concise breakdown footer
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    med_count = sum(1 for f in findings if f.severity == "MEDIUM")
    low_count = sum(1 for f in findings if f.severity == "LOW")

    breakdown_parts = [
        f"[bold red]{high_count} HIGH[/bold red]",
        f"[bold yellow]{med_count} MEDIUM[/bold yellow]",
        f"[bold blue]{low_count} LOW[/bold blue]",
    ]
    if stats and stats.get("suppressed_count", 0) > 0:
        breakdown_parts.append(f"[dim]{stats['suppressed_count']} suppressed[/dim]")

    console.print()
    console.print(f"[bold]Breakdown:[/bold] {'  •  '.join(breakdown_parts)}")
    console.print()


def print_blocked_commit(findings: List[ScanFinding]) -> None:
    """Display the EnvGuard blocked commit alert screen with guidance."""
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    med_count = sum(1 for f in findings if f.severity == "MEDIUM")

    header_content = Group(
        Text(""),
        Align.center(Text("ENVGUARD BLOCKED COMMIT", style="bold red")),
        Text(""),
        Align.center(Text("Blocking security findings were detected in staged changes.", style="white")),
        Text(""),
        Align.center(Text.from_markup(f"[bold red]HIGH:   {high_count}[/bold red]     [bold yellow]MEDIUM: {med_count}[/bold yellow]")),
        Text(""),
    )
    console.print()
    console.print(Panel(header_content, border_style="red", box=box.ROUNDED, expand=False, padding=(0, 2)))
    console.print()

    # Table of blocking findings
    table = Table(
        title="[bold red]Blocking Staged Findings[/bold red]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold red",
        expand=False,
    )
    table.add_column("Severity", justify="center", style="bold")
    table.add_column("Rule ID", style="bold")
    table.add_column("File")
    table.add_column("Line", justify="right")
    table.add_column("Masked Value", style="cyan")
    table.add_column("Signals", style="magenta")

    for f in findings:
        table.add_row(
            format_severity(f.severity),
            f.rule_id,
            f.file_path,
            str(f.line_number),
            f.masked_value,
            format_signals(f),
        )

    console.print(table)
    console.print()

    # Generic Remediation Steps
    steps = (
        "[bold cyan]1.[/bold cyan] Remove sensitive credentials from staged files.\n"
        "[bold cyan]2.[/bold cyan] Store credentials using secure environment configuration.\n"
        "[bold cyan]3.[/bold cyan] Rotate credentials if a real secret was exposed.\n"
        "[bold cyan]4.[/bold cyan] Stage the corrected files and try again."
    )
    console.print(
        Panel(
            steps,
            title="[bold]Next Steps[/bold]",
            border_style="yellow",
            box=box.ROUNDED,
            expand=False,
            padding=(0, 2),
        )
    )
    console.print()


def print_check_passed(low_findings_count: int = 0, no_staged: bool = False) -> None:
    """Display clean success screen for git check."""
    console.print()
    if no_staged:
        console.print(
            create_success_panel(
                "CHECK PASSED",
                "No staged Git changes to check.\n[dim]Stage files with 'git add' to scan before committing.[/dim]",
            )
        )
    else:
        msg = "No blocking secrets were detected in the staged Git changes."
        if low_findings_count > 0:
            msg += f"\n\n[bold blue]Notice:[/bold blue] {low_findings_count} low-severity warning(s) detected (non-blocking)."
        console.print(create_success_panel("CHECK PASSED", msg))
    console.print()


def print_diff_report(diff_result: EnvDiffResult) -> None:
    """Print environment variable drift comparison results."""
    console.print()
    if not diff_result.has_drift:
        console.print(
            create_success_panel(
                "ENVIRONMENT SYNCHRONIZED",
                f".env and .env.example are synchronized ({diff_result.env_keys_count} variables).",
            )
        )
        console.print()
        return

    header = (
        "[bold]ENVIRONMENT CONFIGURATION DRIFT[/bold]\n\n"
        f"[bold].env variables:[/bold] {diff_result.env_keys_count}      "
        f"[bold].env.example variables:[/bold] {diff_result.example_keys_count}"
    )
    console.print(Panel(header, border_style="yellow", box=box.ROUNDED, expand=False, padding=(0, 2)))
    console.print()

    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold yellow",
        expand=False,
    )
    table.add_column("Status", style="bold")
    table.add_column("Environment Variable", style="white")

    if diff_result.missing_from_example:
        for key in diff_result.missing_from_example:
            table.add_row("[bold red]Missing from .env.example[/bold red]", f"[red]✗[/red] {key}")

    if diff_result.extra_in_example:
        if diff_result.missing_from_example:
            table.add_section()
        for key in diff_result.extra_in_example:
            table.add_row("[bold yellow]Extra in .env.example[/bold yellow]", f"[yellow]⚠[/yellow] {key}")

    console.print(table)
    console.print()


def print_status_dashboard(
    is_git: bool,
    env_tracked: bool,
    findings: List[ScanFinding],
    diff_result: Optional[EnvDiffResult],
    diff_error: Optional[str],
    hook_installed: bool,
    config_status: Optional[str] = None,
    baseline_status: Optional[str] = None,
) -> str:
    """Render comprehensive EnvGuard security status report and return status label."""
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    med_count = sum(1 for f in findings if f.severity == "MEDIUM")
    low_count = sum(1 for f in findings if f.severity == "LOW")
    has_drift = diff_result is not None and diff_result.has_drift

    # Compute overall status
    explanation = ""
    if env_tracked or high_count > 0:
        overall_label = "CRITICAL"
        border_style = "red"
        reasons = []
        if high_count > 0:
            reasons.append(f"{high_count} High severity secret(s) detected in repository")
        if env_tracked:
            reasons.append(".env file is tracked in Git")
        explanation = " • ".join(reasons) + "."
    elif med_count > 0 or has_drift or not hook_installed:
        overall_label = "ATTENTION REQUIRED"
        border_style = "yellow"
        reasons = []
        if med_count > 0:
            reasons.append(f"{med_count} Medium severity finding(s)")
        if has_drift:
            reasons.append(f"{len(diff_result.missing_from_example)} variable(s) missing from .env.example" if diff_result.missing_from_example else "Environment drift detected")
        if not hook_installed:
            reasons.append("Pre-commit hook not installed")
        explanation = " • ".join(reasons) + "."
    elif low_count > 0:
        overall_label = "WARNING"
        border_style = "blue"
        explanation = f"{low_count} low-severity warning(s) detected."
    else:
        overall_label = "SECURE"
        border_style = "green"
        explanation = "All security checks passed. Repository is protected."

    table = Table(
        title="[bold]ENVGUARD PROJECT STATUS[/bold]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        expand=False,
    )
    table.add_column("Check", style="bold", min_width=24)
    table.add_column("Status", min_width=18)

    # 1. Git Repository
    table.add_row(
        "Git Repository",
        "[green]DETECTED[/green]" if is_git else "[yellow]NOT DETECTED[/yellow]",
    )

    # 2. Secrets
    if high_count > 0:
        table.add_row("Secrets", f"[bold red]CRITICAL ({high_count} HIGH, {med_count} MED)[/bold red]")
    elif med_count > 0:
        table.add_row("Secrets", f"[bold yellow]ATTENTION ({med_count} MED)[/bold yellow]")
    elif low_count > 0:
        table.add_row("Secrets", f"[bold blue]WARNING ({low_count} LOW)[/bold blue]")
    else:
        table.add_row("Secrets", "[green]CLEAN[/green]")

    # 3. .env Tracked
    if env_tracked:
        table.add_row(".env Tracked", "[bold red]YES (ALERT)[/bold red]")
    else:
        table.add_row(".env Tracked", "[green]NO[/green]")

    # 4. .env.example Sync
    if diff_error:
        table.add_row(".env.example Sync", f"[dim]{diff_error}[/dim]")
    elif diff_result and diff_result.has_drift:
        drift_desc = []
        if diff_result.missing_from_example:
            drift_desc.append(f"{len(diff_result.missing_from_example)} missing")
        if diff_result.extra_in_example:
            drift_desc.append(f"{len(diff_result.extra_in_example)} extra")
        table.add_row(".env.example Sync", f"[bold yellow]ATTENTION ({', '.join(drift_desc)})[/bold yellow]")
    elif diff_result:
        table.add_row(".env.example Sync", "[green]SYNCHRONIZED[/green]")
    else:
        table.add_row(".env.example Sync", "[dim]NOT FOUND[/dim]")

    # 5. Pre-commit Hook
    if hook_installed:
        table.add_row("Pre-Commit Hook", "[green]INSTALLED[/green]")
    else:
        table.add_row("Pre-Commit Hook", "[yellow]NOT INSTALLED[/yellow]")

    # 6. Configuration
    if config_status:
        table.add_row("Configuration", config_status)
    else:
        table.add_row("Configuration", "[green]VALID[/green]")

    # 7. Baseline
    if baseline_status:
        table.add_row("Baseline", baseline_status)
    else:
        table.add_row("Baseline", "[dim]NOT FOUND[/dim]")

    console.print()
    console.print(table)
    console.print()

    # Overall Status Panel
    status_content = (
        f"[bold]OVERALL STATUS:[/bold] [bold {border_style}]{overall_label}[/bold {border_style}]\n\n"
        f"{explanation}"
    )
    console.print(
        Panel(
            status_content,
            border_style=border_style,
            box=box.ROUNDED,
            expand=False,
            padding=(0, 2),
        )
    )
    console.print()
    return overall_label


def print_hook_installed(message: str) -> None:
    """Display clear, professional feedback upon pre-commit hook installation."""
    is_refreshed = "already installed and has been refreshed" in message
    is_appended = "Safely appended" in message

    if is_refreshed:
        title = "Hook Refreshed"
        desc = "EnvGuard pre-commit hook was refreshed to the latest version.\nExisting hooks were preserved."
    elif is_appended:
        title = "Hook Appended"
        desc = "EnvGuard pre-commit hook was safely appended to your existing pre-commit script.\nExisting hooks were preserved."
    else:
        title = "Hook Installed"
        desc = "EnvGuard pre-commit protection is now active."

    content = (
        f"{desc}\n\n"
        "[bold]The following command will run automatically before commits:[/bold]\n"
        "  [cyan]envguard check[/cyan]\n\n"
        "[dim]Note: Ensure 'envguard' is accessible in your system PATH.[/dim]"
    )
    console.print()
    console.print(
        Panel(
            content,
            title=f"[bold green]{title}[/bold green]",
            border_style="green",
            box=box.ROUNDED,
            expand=False,
            padding=(0, 2),
        )
    )
    console.print()


def print_init_result(result: InitResult) -> None:
    """Display initialization status for configuration and ignore files."""
    table = Table(
        title="[bold]EnvGuard Initialization[/bold]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        expand=False,
    )
    table.add_column("File", style="bold", min_width=20)
    table.add_column("Status", min_width=20)
    table.add_column("Path")

    # Config row
    if result.config_created:
        config_status = "[bold green]Created[/bold green]"
    else:
        config_status = "[yellow]Already Exists[/yellow]"
    table.add_row(".envguard.yml", config_status, result.config_path)

    # Ignore row
    if result.ignore_created:
        ignore_status = "[bold green]Created[/bold green]"
    else:
        ignore_status = "[yellow]Already Exists[/yellow]"
    table.add_row(".envguardignore", ignore_status, result.ignore_path)

    console.print()
    console.print(table)
    console.print()
    console.print("[dim]Edit .envguard.yml to configure scan thresholds and .envguardignore to exclude files.[/dim]")
    console.print()


def print_diagnostics(report: DiagnosticReport) -> None:
    """Display system diagnostics and doctor check recommendations."""
    table = Table(
        title="[bold]EnvGuard Diagnostics (Doctor)[/bold]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        expand=False,
    )
    table.add_column("Check", style="bold", min_width=22)
    table.add_column("Status", justify="center", min_width=12)
    table.add_column("Details")

    for c in report.checks:
        if c.status == "PASS":
            status_text = "[bold green]PASS[/bold green]"
        elif c.status == "WARNING":
            status_text = "[bold yellow]WARNING[/bold yellow]"
        else:
            status_text = "[bold red]ERROR[/bold red]"

        detail_text = c.details
        if c.recommendation:
            detail_text += f"\n[dim]Recommendation: {c.recommendation}[/dim]"

        table.add_row(c.name, status_text, detail_text)

    console.print()
    console.print(table)

    summary_text = (
        f"[bold]Summary:[/bold] "
        f"[green]{report.passed_count} Passed[/green]  •  "
        f"[yellow]{report.warning_count} Warnings[/yellow]  •  "
        f"[red]{report.error_count} Errors[/red]"
    )
    console.print()
    console.print(summary_text)
    console.print()


def print_rule_explanation(pattern: Pattern) -> None:
    """Display detailed rule explanation with background and remediation."""
    table = Table(box=box.ROUNDED, show_header=False, expand=False)
    table.add_column("Property", style="bold cyan", min_width=16)
    table.add_column("Value")

    table.add_row("Rule ID", f"[bold]{pattern.id}[/bold]")
    table.add_row("Name", pattern.name)
    table.add_row("Severity", format_severity(pattern.severity))
    table.add_row("State", "[green]Enabled[/green]" if pattern.enabled else "[red]Disabled[/red]")
    table.add_row("Regex", f"[dim]{pattern.regex}[/dim]")
    table.add_row("Detects", getattr(pattern, "detects", pattern.description))
    table.add_row("Why it matters", getattr(pattern, "why_it_matters", "Security hazard"))
    table.add_row("Remediation", getattr(pattern, "remediation", "Move secret to environment variable"))

    console.print()
    console.print(
        Panel(
            table,
            title=f"[bold]Rule Explanation: {pattern.id}[/bold]",
            border_style="cyan",
            box=box.ROUNDED,
            expand=False,
            padding=(0, 1),
        )
    )
    console.print()


def print_rules_list(patterns: List[Pattern]) -> None:
    """Display catalog of all configured detection rules."""
    table = Table(
        title="[bold]EnvGuard Detection Rules[/bold]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        expand=False,
    )
    table.add_column("Rule ID", style="bold", min_width=22)
    table.add_column("Severity", justify="center", min_width=10)
    table.add_column("State", justify="center", min_width=10)
    table.add_column("Description")

    for p in patterns:
        state_text = "[green]Enabled[/green]" if p.enabled else "[dim red]Disabled[/dim red]"
        table.add_row(
            p.id,
            format_severity(p.severity),
            state_text,
            p.description,
        )

    console.print()
    console.print(table)
    console.print()
    console.print(f"[dim]Total rules: {len(patterns)} | Use 'envguard explain <rule-id>' for details.[/dim]")
    console.print()
