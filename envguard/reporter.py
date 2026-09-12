import json
import sys
from typing import Any, Dict, List, Optional

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from envguard import __version__
from envguard.env_diff import EnvDiffResult
from envguard.scanner import ScanFinding

console = Console()
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
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": f.severity,
                "file": f.file_path.replace("\\", "/"),
                "line": f.line_number,
                "masked_value": f.masked_value,
                "fingerprint": f.fingerprint,
            }
            for f in findings
        ],
    }
    print_json(data)


def render_check_json(
    blocking_findings: List[ScanFinding],
    low_findings: List[ScanFinding],
    no_staged: bool = False,
) -> None:
    """Output git check result in structured JSON format."""
    all_findings = blocking_findings + low_findings
    status = "failed" if blocking_findings else "passed"
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
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": f.severity,
                "file": f.file_path.replace("\\", "/"),
                "line": f.line_number,
                "masked_value": f.masked_value,
                "fingerprint": f.fingerprint,
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


def print_scan_findings(findings: List[ScanFinding], title: str = "Scan Findings") -> None:
    """Print detailed list of secret scan findings."""
    if not findings:
        console.print("[green]✓ No secrets detected in scanned files.[/green]")
        return

    for finding in findings:
        if finding.severity == "HIGH":
            badge = "[bold red]🔴 HIGH SEVERITY SECRET DETECTED[/bold red]"
            border_style = "red"
        elif finding.severity == "MEDIUM":
            badge = "[bold yellow]🟠 MEDIUM SEVERITY FINDING[/bold yellow]"
            border_style = "yellow"
        else:
            badge = "[bold blue]🟡 LOW SEVERITY WARNING[/bold blue]"
            border_style = "blue"

        body = (
            f"{badge}\n\n"
            f"[bold]File:[/bold] {finding.file_path}\n"
            f"[bold]Line:[/bold] {finding.line_number}\n"
            f"[bold]Rule ID:[/bold] [magenta]{finding.rule_id}[/magenta]\n"
            f"[bold]Rule Name:[/bold] {finding.rule_name}\n"
            f"[bold]Severity:[/bold] {finding.severity}\n"
            f"[bold]Value:[/bold] [cyan]{finding.masked_value}[/cyan]"
        )
        console.print(Panel(body, border_style=border_style, expand=False))
        console.print()

    # Summary table
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    med_count = sum(1 for f in findings if f.severity == "MEDIUM")
    low_count = sum(1 for f in findings if f.severity == "LOW")

    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold")
    summary.add_column()
    summary.add_row("Total Findings:", f"{len(findings)}")
    summary.add_row("High Severity:", f"[red]{high_count}[/red]")
    summary.add_row("Medium Severity:", f"[yellow]{med_count}[/yellow]")
    summary.add_row("Low Severity:", f"[blue]{low_count}[/blue]")

    console.print(Panel(summary, title="[bold]Summary[/bold]", border_style="dim", expand=False))


def print_blocked_commit(findings: List[ScanFinding]) -> None:
    """Display the EnvGuard blocked commit alert banner."""
    header = (
        "[bold white on red]                                    [/bold white on red]\n"
        "[bold white on red]      ENVGUARD BLOCKED COMMIT       [/bold white on red]\n"
        "[bold white on red]                                    [/bold white on red]"
    )
    console.print(Panel(header, border_style="red", expand=False))
    console.print()

    for finding in findings:
        badge = (
            "[bold red]🔴 HIGH SEVERITY SECRET DETECTED[/bold red]"
            if finding.severity == "HIGH"
            else "[bold yellow]🟠 MEDIUM SEVERITY SECRET DETECTED[/bold yellow]"
        )
        body = (
            f"{badge}\n\n"
            f"[bold]File:[/bold] {finding.file_path}\n"
            f"[bold]Line:[/bold] {finding.line_number}\n"
            f"[bold]Rule ID:[/bold] [magenta]{finding.rule_id}[/magenta]\n"
            f"[bold]Rule Name:[/bold] {finding.rule_name}\n"
            f"[bold]Value:[/bold] [cyan]{finding.masked_value}[/cyan]"
        )
        console.print(Panel(body, border_style="red", expand=False))
        console.print()

    console.print("[bold red]Commit blocked to protect your repository.[/bold red]")
    console.print("[yellow]Remove or replace the secret(s), re-stage your changes, and try again.[/yellow]\n")


def print_diff_report(diff_result: EnvDiffResult) -> None:
    """Print environment variable drift comparison results inside a proper panel."""
    if not diff_result.has_drift:
        console.print(Panel("[green]✓ .env and .env.example are synchronized.[/green]", border_style="green", expand=False))
        return

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Status", style="bold")
    table.add_column("Variables")

    if diff_result.missing_from_example:
        vars_str = "\n".join(f"[red]✗[/red] {key}" for key in diff_result.missing_from_example)
        table.add_row("[bold red]Missing from .env.example:[/bold red]", vars_str)

    if diff_result.extra_in_example:
        if diff_result.missing_from_example:
            table.add_section()
        vars_str = "\n".join(f"[yellow]⚠[/yellow] {key}" for key in diff_result.extra_in_example)
        table.add_row("[bold yellow]Extra in .env.example:[/bold yellow]", vars_str)

    console.print()
    console.print(Panel(table, title="[bold]Environment Drift Report[/bold]", border_style="yellow", expand=False))
    console.print()


def print_status_dashboard(
    is_git: bool,
    env_tracked: bool,
    findings: List[ScanFinding],
    diff_result: Optional[EnvDiffResult],
    diff_error: Optional[str],
    hook_installed: bool,
) -> str:
    """Render comprehensive EnvGuard security status report inside a proper panel."""
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    med_count = sum(1 for f in findings if f.severity == "MEDIUM")
    low_count = sum(1 for f in findings if f.severity == "LOW")
    has_drift = diff_result is not None and diff_result.has_drift

    if env_tracked or high_count > 0:
        overall_label = "CRITICAL"
        overall_text = "[bold red]🔴 CRITICAL — IMMEDIATE ACTION REQUIRED[/bold red]"
        border_style = "red"
    elif med_count > 0 or has_drift or not hook_installed:
        overall_label = "ATTENTION REQUIRED"
        overall_text = "[bold yellow]🟠 ATTENTION REQUIRED[/bold yellow]"
        border_style = "yellow"
    elif low_count > 0:
        overall_label = "WARNING"
        overall_text = "[bold blue]🟡 WARNING[/bold blue]"
        border_style = "blue"
    else:
        overall_label = "SECURE"
        overall_text = "[bold green]🟢 SECURE[/bold green]"
        border_style = "green"

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Check", style="bold")
    table.add_column("Status")

    # 1. Git Repository
    table.add_row(
        "Git Repository",
        "[green]✓ YES[/green]" if is_git else "[yellow]✗ NO (not inside a Git repo)[/yellow]",
    )

    # 2. .env tracked
    if env_tracked:
        table.add_row(".env tracked", "[bold red]🔴 YES — SECURITY RISK[/bold red]")
    else:
        table.add_row(".env tracked", "[green]✓ NO[/green]")

    # 3. Secrets detected
    if high_count > 0:
        table.add_row("Secrets detected", f"[bold red]🔴 {high_count} High, {med_count} Medium found[/bold red]")
    elif med_count > 0:
        table.add_row("Secrets detected", f"[bold yellow]🟠 {med_count} Medium found[/bold yellow]")
    elif low_count > 0:
        table.add_row("Secrets detected", f"[bold blue]🟡 {low_count} Low-severity warnings[/bold blue]")
    else:
        table.add_row("Secrets detected", "[green]✓ None[/green]")

    # 4. .env.example sync
    if diff_error:
        table.add_row(".env.example sync", f"[dim]{diff_error}[/dim]")
    elif diff_result and diff_result.has_drift:
        parts = []
        if diff_result.missing_from_example:
            parts.append(f"{len(diff_result.missing_from_example)} missing from example")
        if diff_result.extra_in_example:
            parts.append(f"{len(diff_result.extra_in_example)} extra in example")
        table.add_row(".env.example sync", f"[bold yellow]⚠ {', '.join(parts)}[/bold yellow]")
    elif diff_result:
        table.add_row(".env.example sync", "[green]✓ Synchronized[/green]")
    else:
        table.add_row(".env.example sync", "[dim]No .env files to check[/dim]")

    # 5. Pre-commit hook
    if hook_installed:
        table.add_row("Pre-commit hook", "[green]✓ Installed[/green]")
    else:
        table.add_row("Pre-commit hook", "[yellow]⚠ Not installed (run 'envguard install-hook')[/yellow]")

    # Section divider and Overall Status inside the box
    table.add_section()
    table.add_row("Overall Status", overall_text)

    panel = Panel(
        table,
        title="[bold]EnvGuard Security Report[/bold]",
        border_style=border_style,
        expand=False,
    )
    console.print()
    console.print(panel)
    console.print()
    return overall_label
