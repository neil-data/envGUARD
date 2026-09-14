"""Centralized Rich theme and UI components for EnvGuard.

Provides a unified visual design system across all terminal commands:
- Consistent severity badges (HIGH, MEDIUM, LOW) with explicit text labels.
- Standardized color tokens and status symbols.
- Reusable panel builders and table generators.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from envguard import __version__

# Global Console instances for text UI rendering
console = Console()
err_console = Console(stderr=True)

# Color Tokens
COLOR_HIGH = "red"
COLOR_MEDIUM = "yellow"
COLOR_LOW = "blue"
COLOR_SUCCESS = "green"
COLOR_WARNING = "yellow"
COLOR_ERROR = "red"
COLOR_INFO = "cyan"
COLOR_MUTED = "dim"
COLOR_TITLE = "bold white"

# Status Symbols
SYMBOL_SUCCESS = "[bold green]✓[/bold green]"
SYMBOL_WARNING = "[bold yellow]⚠[/bold yellow]"
SYMBOL_ERROR = "[bold red]✗[/bold red]"
SYMBOL_INFO = "[bold cyan]ℹ[/bold cyan]"

# Explicit Text Severity Badges
BADGE_HIGH = "[bold red]HIGH[/bold red]"
BADGE_MEDIUM = "[bold yellow]MEDIUM[/bold yellow]"
BADGE_LOW = "[bold blue]LOW[/bold blue]"


def format_severity(severity: str) -> str:
    """Return a consistently styled severity label with text."""
    sev_upper = severity.upper()
    if sev_upper == "HIGH":
        return BADGE_HIGH
    elif sev_upper == "MEDIUM":
        return BADGE_MEDIUM
    else:
        return BADGE_LOW


def create_panel(
    renderable: Any,
    title: Optional[str] = None,
    border_style: str = "cyan",
    panel_box: Any = box.ROUNDED,
    expand: bool = False,
    padding: tuple = (0, 1),
) -> Panel:
    """Create a standardized Rich Panel."""
    return Panel(
        renderable,
        title=f"[bold]{title}[/bold]" if title else None,
        border_style=border_style,
        box=panel_box,
        expand=expand,
        padding=padding,
    )


def create_header_panel() -> Panel:
    """Create the professional branded EnvGuard header panel for interactive modes."""
    content = Group(
        Text(""),
        Align.center(Text("ENVGUARD", style="bold cyan")),
        Align.center(Text("Developer Security Safety Gate", style="bold white")),
        Text(""),
        Align.center(Text("Secrets • Git Protection • Environment Validation", style="dim")),
        Text(""),
    )
    return Panel(
        content,
        box=box.ROUNDED,
        border_style="cyan",
        expand=False,
        padding=(0, 4),
    )


def create_project_context_table(cwd: Path, is_git: bool) -> Table:
    """Render project context metadata in a clean grid."""
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()
    table.add_row("Project:", f"[cyan]{cwd.name}[/cyan]")
    table.add_row("Path:", f"[dim]{cwd}[/dim]")
    table.add_row("EnvGuard:", f"[green]v{__version__}[/green]")
    table.add_row(
        "Git Repository:",
        "[green]Detected[/green]" if is_git else "[yellow]Not Detected[/yellow]",
    )
    return table


def create_success_panel(title: str, message: str) -> Panel:
    """Create a clean, focused success message panel."""
    content = Group(
        Align.center(Text(title.upper(), style="bold green")),
        Text(""),
        Align.center(Text.from_markup(message)),
    )
    return Panel(
        content,
        border_style="green",
        box=box.ROUNDED,
        expand=False,
        padding=(0, 2),
    )


def create_error_panel(
    title: str,
    reason: str,
    suggestion: Optional[str] = None,
    verbose_hint: bool = True,
) -> Panel:
    """Create a human-friendly error panel."""
    parts = [f"[bold]Reason:[/bold]\n{reason}"]
    if suggestion:
        parts.append(f"[bold]Suggestion:[/bold]\n{suggestion}")
    if verbose_hint:
        parts.append("[dim]Run with --verbose for technical details.[/dim]")

    return Panel(
        "\n\n".join(parts),
        title=f"[bold red]{title}[/bold red]",
        border_style="red",
        box=box.ROUNDED,
        expand=False,
        padding=(0, 1),
    )


def create_summary_panel(
    files_scanned: int,
    files_skipped: int,
    findings_count: int,
) -> Panel:
    """Render the concise Scan Complete summary panel."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold")
    grid.add_column()
    grid.add_row("Files scanned:", str(files_scanned))
    grid.add_row("Files skipped:", str(files_skipped))
    grid.add_row(
        "Findings:",
        f"[bold red]{findings_count}[/bold red]" if findings_count > 0 else "[green]0[/green]",
    )

    border_color = "red" if findings_count > 0 else "green"
    return Panel(
        grid,
        title="[bold]Scan Complete[/bold]",
        border_style=border_color,
        box=box.ROUNDED,
        expand=False,
        padding=(0, 2),
    )
