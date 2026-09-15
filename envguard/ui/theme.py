"""Centralized Rich theme and UI components for EnvGuard.

Single source of truth for all terminal styling in EnvGuard v0.7.5:
- Consistent severity tokens and badges (HIGH, MEDIUM, LOW) with explicit text labels.
- Standardized status tokens and badges (PASS, WARNING, ERROR, BLOCKED, CLEAN, CRITICAL).
- Centralized masked-value styling (COLOR_MASKED).
- Reusable panel builders and table generators.
- Syntax-highlighted code snippet renderer with strict pre-highlight secret masking.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich import box
from rich.align import Align
from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.syntax import Syntax
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
COLOR_MASKED = "cyan"

# Severity Style Mappings
SEVERITY_STYLES: Dict[str, str] = {
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold blue",
}

# Explicit Text Severity Badges
BADGE_HIGH = "[bold red]HIGH[/bold red]"
BADGE_MEDIUM = "[bold yellow]MEDIUM[/bold yellow]"
BADGE_LOW = "[bold blue]LOW[/bold blue]"

# Status Badges
BADGE_PASS = "[bold green]PASS[/bold green]"
BADGE_WARNING = "[bold yellow]WARNING[/bold yellow]"
BADGE_ERROR = "[bold red]ERROR[/bold red]"
BADGE_BLOCKED = "[bold red]BLOCKED[/bold red]"
BADGE_CLEAN = "[bold green]CLEAN[/bold green]"
BADGE_CRITICAL = "[bold red]CRITICAL[/bold red]"

# Status Style Mappings
STATUS_STYLES: Dict[str, str] = {
    "PASS": "bold green",
    "WARNING": "bold yellow",
    "ERROR": "bold red",
    "BLOCKED": "bold red",
    "CLEAN": "bold green",
    "CRITICAL": "bold red",
}

# Status Symbols
SYMBOL_SUCCESS = "[bold green]\u2713[/bold green]"
SYMBOL_WARNING = "[bold yellow]\u26a0[/bold yellow]"
SYMBOL_ERROR = "[bold red]\u2717[/bold red]"
SYMBOL_INFO = "[bold cyan]\u2139[/bold cyan]"


def format_severity(severity: str) -> str:
    """Return a consistently styled severity label with text."""
    sev_upper = (severity or "").strip().upper()
    if sev_upper == "HIGH":
        return BADGE_HIGH
    elif sev_upper == "MEDIUM":
        return BADGE_MEDIUM
    else:
        return BADGE_LOW


def format_status(status: str) -> str:
    """Return a consistently styled status label with text."""
    status_upper = (status or "").strip().upper()
    if status_upper == "PASS":
        return BADGE_PASS
    elif status_upper == "WARNING":
        return BADGE_WARNING
    elif status_upper == "ERROR":
        return BADGE_ERROR
    elif status_upper == "BLOCKED":
        return BADGE_BLOCKED
    elif status_upper == "CLEAN":
        return BADGE_CLEAN
    elif status_upper == "CRITICAL":
        return BADGE_CRITICAL
    return f"[bold]{status}[/bold]"


def create_panel(
    renderable: Any,
    title: Optional[str] = None,
    border_style: str = "cyan",
    panel_box: Any = box.ROUNDED,
    expand: bool = False,
    padding: Tuple[int, int] = (0, 1),
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
        Align.center(Text("Secrets \u2022 Git Protection \u2022 Environment Validation", style="dim")),
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


def create_warning_panel(
    title: str,
    message: str,
    suggestion: Optional[str] = None,
) -> Panel:
    """Create a human-friendly warning panel."""
    parts = [message]
    if suggestion:
        parts.append(f"[bold]Suggestion:[/bold]\n{suggestion}")
    return Panel(
        "\n\n".join(parts),
        title=f"[bold yellow]{title}[/bold yellow]",
        border_style="yellow",
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


def create_standard_table(
    title: Optional[str] = None,
    columns: Optional[List[Dict[str, Any]]] = None,
    box_style: Any = box.ROUNDED,
    show_header: bool = True,
    header_style: str = "bold",
) -> Table:
    """Create a standardized EnvGuard Table with unified styling."""
    tbl = Table(
        title=f"[bold]{title}[/bold]" if title else None,
        box=box_style,
        show_header=show_header,
        header_style=header_style,
    )
    if columns:
        for col in columns:
            name = col.get("name", "")
            style = col.get("style")
            justify = col.get("justify", "left")
            no_wrap = col.get("no_wrap", False)
            overflow = col.get("overflow", "ellipsis")
            tbl.add_column(name, style=style, justify=justify, no_wrap=no_wrap, overflow=overflow)
    return tbl


_EXTENSION_LEXERS = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".json": "json",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".toml": "toml",
    ".sh": "bash",
    ".bash": "bash",
    ".zsh": "bash",
    ".env": "bash",
    ".ini": "ini",
    ".cfg": "ini",
    ".conf": "ini",
    ".xml": "xml",
    ".html": "html",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".rb": "ruby",
    ".php": "php",
    ".sql": "sql",
    ".md": "markdown",
}


def render_finding_snippet(
    raw_snippet: Optional[str],
    raw_value: Optional[str] = None,
    masked_value: Optional[str] = None,
    file_path: Optional[str] = None,
    line_number: Optional[int] = None,
    theme: str = "monokai",
) -> Optional[Syntax]:
    """Render a syntax-highlighted code snippet with STRICT pre-highlight secret masking.

    Security Guarantee:
    raw_value is replaced by masked_value BEFORE passing into rich.syntax.Syntax.
    Plaintext secrets NEVER enter the syntax lexer or resulting AST.
    """
    if not raw_snippet:
        return None

    # Step 1: Pre-highlight masking
    safe_snippet = raw_snippet
    if raw_value and masked_value and raw_value in safe_snippet:
        safe_snippet = safe_snippet.replace(raw_value, masked_value)

    # Step 2: Determine lexer from file extension
    lexer = "text"
    if file_path:
        suffix = Path(file_path).suffix.lower()
        lexer = _EXTENSION_LEXERS.get(suffix, "text")

    # Step 3: Instantiate Syntax object with line numbering
    start_line = line_number if (line_number and line_number > 0) else 1
    return Syntax(
        safe_snippet,
        lexer=lexer,
        theme=theme,
        line_numbers=True if (line_number and line_number > 0) else False,
        start_line=start_line,
        word_wrap=True,
        background_color="default",
    )
