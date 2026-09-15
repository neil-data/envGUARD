"""Filesystem watch mode for EnvGuard v0.7.0.

Provides debounced filesystem monitoring and instant secret detection on file saves
using standard library os.scandir/os.walk with zero external dependencies.
"""

from datetime import datetime
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from envguard.config import EnvGuardConfig, find_config_file, load_config
from envguard.ignore import is_path_ignored, load_envguardignore
from envguard.patterns import Pattern, load_default_patterns
from envguard.reporter import format_signals
from envguard.scanner import (
    DEFAULT_MAX_BYTES,
    ScanFinding,
    compile_exclude_spec,
    load_root_gitignore,
    scan_file_streaming,
)
from envguard.theme import (
    COLOR_HIGH,
    COLOR_LOW,
    COLOR_MEDIUM,
    console,
    create_panel,
    err_console,
    format_severity,
    render_finding_snippet,
)
from rich import box
from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

BUILTIN_IGNORED_DIRS: Set[str] = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "venv",
    ".venv",
    "env",
    ".env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    ".idea",
    ".vscode",
    "build",
    "dist",
    ".eggs",
    ".envguard_cache",
}


class FileWatcher:
    """Monitors directory for file changes and triggers debounced scans."""

    def __init__(
        self,
        target_path: Path,
        config: Optional[EnvGuardConfig] = None,
        patterns: Optional[List[Pattern]] = None,
        poll_interval: float = 0.4,
        debounce_delay: float = 0.3,
    ) -> None:
        self.root = target_path.resolve()
        self.poll_interval = poll_interval
        self.debounce_delay = debounce_delay

        if config is None:
            cfg_file = find_config_file(self.root)
            self.config = load_config(root_dir=self.root, config_path=cfg_file)
        else:
            self.config = config

        if patterns is None:
            self.patterns = load_default_patterns(
                disabled_rules=self.config.disabled_rules,
                severity_overrides=self.config.severity_overrides,
            )
        else:
            self.patterns = patterns

        self.gitignore_spec = load_root_gitignore(self.root)
        self.envguardignore_spec = load_envguardignore(self.root)
        self.config_exclude_spec = compile_exclude_spec(self.config.exclude)

        # File state: rel_path -> (mtime_ns, size)
        self.snapshot: Dict[str, Tuple[int, int]] = {}
        # Pending changes for debounce: rel_path -> first_detected_time
        self.pending_changes: Dict[str, float] = {}

    def is_dir_ignored(self, dir_rel: str) -> bool:
        """Check if directory name matches builtin ignore or path ignore rules."""
        basename = dir_rel.split("/")[-1]
        if basename in BUILTIN_IGNORED_DIRS:
            return True
        ignored, _ = is_path_ignored(
            rel_path=dir_rel,
            gitignore_spec=self.gitignore_spec,
            envguardignore_spec=self.envguardignore_spec,
            config_exclude_spec=self.config_exclude_spec,
            is_dir=True,
        )
        return ignored

    def is_file_ignored(self, file_rel: str) -> bool:
        """Check if file matches ignore rules or exclusions."""
        ignored, _ = is_path_ignored(
            rel_path=file_rel,
            gitignore_spec=self.gitignore_spec,
            envguardignore_spec=self.envguardignore_spec,
            config_exclude_spec=self.config_exclude_spec,
            is_dir=False,
        )
        return ignored

    def scan_tree(self) -> Dict[str, Tuple[int, int]]:
        """Traverse monitored path and return current mapping of rel_path -> (mtime_ns, size)."""
        current_state: Dict[str, Tuple[int, int]] = {}
        if not self.root.exists():
            return current_state

        if self.root.is_file():
            rel_path = self.root.name
            if not self.is_file_ignored(rel_path):
                try:
                    stat = self.root.stat()
                    current_state[rel_path] = (stat.st_mtime_ns, stat.st_size)
                except OSError:
                    pass
            return current_state

        for dirpath, dirnames, filenames in os.walk(self.root):
            rel_dir = str(Path(dirpath).relative_to(self.root)).replace("\\", "/")

            # Prune ignored subdirectories in-place
            kept_dirs = []
            for d in dirnames:
                sub_rel = f"{rel_dir}/{d}" if rel_dir != "." else d
                if not self.is_dir_ignored(sub_rel):
                    kept_dirs.append(d)
            dirnames[:] = kept_dirs

            for fname in filenames:
                file_rel = f"{rel_dir}/{fname}" if rel_dir != "." else fname
                if self.is_file_ignored(file_rel):
                    continue
                full_file = Path(dirpath) / fname
                try:
                    stat = full_file.stat()
                    current_state[file_rel] = (stat.st_mtime_ns, stat.st_size)
                except OSError:
                    # File was deleted or permission denied
                    continue

        return current_state

    def initialize_snapshot(self) -> None:
        """Build initial baseline state without triggering detections."""
        self.snapshot = self.scan_tree()

    def check_for_changes(self) -> List[str]:
        """Poll tree and return batch of changed relative file paths ready for scan."""
        current_tree = self.scan_tree()
        now = time.time()

        # Detect additions and modifications
        for rel_path, state in current_tree.items():
            prev_state = self.snapshot.get(rel_path)
            if prev_state != state:
                if rel_path not in self.pending_changes:
                    self.pending_changes[rel_path] = now

        # Detect deletions
        deleted_keys = [k for k in self.snapshot if k not in current_tree]
        for d in deleted_keys:
            del self.snapshot[d]
            if d in self.pending_changes:
                del self.pending_changes[d]

        # Determine which pending changes have settled past debounce window
        ready_files: List[str] = []
        for rel_path, detected_time in list(self.pending_changes.items()):
            if now - detected_time >= self.debounce_delay:
                ready_files.append(rel_path)
                del self.pending_changes[rel_path]
                if rel_path in current_tree:
                    self.snapshot[rel_path] = current_tree[rel_path]

        return ready_files

    def scan_file_rel(self, rel_path: str) -> List[ScanFinding]:
        """Scan a single changed relative path using streaming detection."""
        full_path = self.root / rel_path if self.root.is_dir() else self.root
        if not full_path.is_file():
            return []

        findings, _ = scan_file_streaming(
            file_path=full_path,
            rel_path_str=rel_path,
            patterns=self.patterns,
            max_file_size_bytes=self.config.max_file_size_bytes,
            advanced_config=self.config.advanced_detection,
        )

        for f in findings:
            f.repository = self.root.name
            f.blocked_by = f.determine_blocking(
                local_block_on=self.config.local_block_on or self.config.block_on,
                org_block_on=self.config.org_config.block_on if self.config.org_config else None,
            )

        return findings

    def create_status_panel(self, status: str = "IDLE", last_event: str = "Watching for file modifications") -> Panel:
        """Create a compact live monitoring status dashboard."""
        total_tracked = len(self.snapshot)
        ts = datetime.now().strftime("%H:%M:%S")

        status_badge = "[bold green]IDLE[/bold green]"
        border_color = "cyan"
        if status == "SCANNING":
            status_badge = "[bold yellow]SCANNING[/bold yellow]"
            border_color = "yellow"
        elif status == "ALERT":
            status_badge = "[bold red]ALERT[/bold red]"
            border_color = "red"
        elif status == "CLEAN":
            status_badge = "[bold green]CLEAN[/bold green]"
            border_color = "green"

        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold")
        grid.add_column()
        grid.add_row("Directory:", f"[cyan]{self.root}[/cyan]")
        grid.add_row("Tracked Files:", f"[dim]{total_tracked}[/dim]")
        grid.add_row("Status:", status_badge)
        grid.add_row("Last Checked:", f"[dim]{ts}[/dim]")
        grid.add_row("Activity:", f"{last_event}")

        return Panel(
            grid,
            title="[bold cyan]EnvGuard Watcher[/bold cyan]",
            border_style=border_color,
            box=box.ROUNDED,
            expand=False,
            padding=(0, 1),
        )

    def print_batch_results(self, rel_path: str, findings: List[ScanFinding]) -> None:
        """Render watch results for a modified file to terminal."""
        ts = datetime.now().strftime("%H:%M:%S")
        if not findings:
            console.print(f"[dim]{ts}[/dim] [green]✓[/green] [bold]{rel_path}[/bold] — Clean (no secrets detected)")
            return

        high_count = sum(1 for f in findings if f.severity == "HIGH")
        med_count = sum(1 for f in findings if f.severity == "MEDIUM")
        low_count = sum(1 for f in findings if f.severity == "LOW")

        summary_parts = []
        if high_count:
            summary_parts.append(f"[bold red]{high_count} HIGH[/bold red]")
        if med_count:
            summary_parts.append(f"[bold yellow]{med_count} MEDIUM[/bold yellow]")
        if low_count:
            summary_parts.append(f"[bold blue]{low_count} LOW[/bold blue]")
        summary_str = ", ".join(summary_parts)

        console.print(f"\n[dim]{ts}[/dim] [red]✗[/red] [bold red]{rel_path}[/bold red] — Leaks detected ({summary_str})")

        table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold",
            padding=(0, 1),
            expand=False,
        )
        table.add_column("Severity", justify="center")
        table.add_column("Rule ID", style="bold")
        table.add_column("Line:Col", justify="right")
        table.add_column("Masked Value", style="cyan")
        table.add_column("Signals", style="magenta")
        has_blocked = any(bool(f.blocked_by) for f in findings)
        if has_blocked:
            table.add_column("Blocked By", style="bold yellow")

        for f in findings:
            col_str = f"{f.line_number}:{getattr(f, 'column', 1) or 1}"
            row = [
                format_severity(f.severity),
                f.rule_id,
                col_str,
                f.masked_value,
                format_signals(f),
            ]
            if has_blocked:
                row.append(f.blocked_by.title() if f.blocked_by else "")
            table.add_row(*row)

        console.print(table)

        # Render code snippet if available
        for f in findings:
            if getattr(f, "line_snippet", None):
                snippet = render_finding_snippet(
                    raw_snippet=f.line_snippet,
                    raw_value=f.raw_value,
                    masked_value=f.masked_value,
                    file_path=f.file_path,
                    line_number=f.line_number,
                )
                if snippet:
                    console.print(
                        create_panel(
                            snippet,
                            title=f"[bold]{f.file_path}[/bold]:{f.line_number} — [bold red]{f.rule_name}[/bold red]",
                            border_style="red" if f.severity == "HIGH" else "yellow",
                            padding=(0, 1),
                        )
                    )
        console.print()

    def run(self, max_iterations: Optional[int] = None) -> None:
        """Start the file watching loop."""
        self.initialize_snapshot()

        is_interactive = sys.stdout.isatty() and not os.environ.get("CI") and max_iterations is None

        if is_interactive:
            try:
                with Live(
                    self.create_status_panel("IDLE", "Watching for file modifications"),
                    console=console,
                    refresh_per_second=4,
                    transient=False,
                ) as live:
                    iterations = 0
                    while True:
                        ready_files = self.check_for_changes()
                        if ready_files:
                            live.update(self.create_status_panel("SCANNING", f"Scanning {len(ready_files)} modified file(s)..."))
                            for rel_path in ready_files:
                                findings = self.scan_file_rel(rel_path)
                                # Print findings outside live panel to preserve scrollable history
                                console.print()
                                self.print_batch_results(rel_path, findings)
                            status_label = "ALERT" if any(len(self.scan_file_rel(p)) > 0 for p in ready_files) else "CLEAN"
                            live.update(self.create_status_panel(status_label, f"Processed {len(ready_files)} file(s)"))
                        else:
                            live.update(self.create_status_panel("IDLE", "Watching for file modifications"))

                        iterations += 1
                        if max_iterations is not None and iterations >= max_iterations:
                            break

                        time.sleep(self.poll_interval)
            except KeyboardInterrupt:
                console.print("\n[dim]EnvGuard Watcher stopped.[/dim]")
                sys.exit(0)
        else:
            console.print()
            console.print("[bold green]EnvGuard Watcher[/bold green] is active.")
            console.print(f"Monitoring: [cyan]{self.root}[/cyan] ([dim]{len(self.snapshot)} file(s) tracked[/dim])")
            console.print("Press [bold]Ctrl+C[/bold] to exit.\n")

            iterations = 0
            try:
                while True:
                    ready_files = self.check_for_changes()
                    for rel_path in ready_files:
                        findings = self.scan_file_rel(rel_path)
                        self.print_batch_results(rel_path, findings)

                    iterations += 1
                    if max_iterations is not None and iterations >= max_iterations:
                        break

                    time.sleep(self.poll_interval)
            except KeyboardInterrupt:
                console.print("\n[dim]EnvGuard Watcher stopped.[/dim]")
                sys.exit(0)


def run_watch(
    target_path: Optional[Path] = None,
    max_iterations: Optional[int] = None,
    poll_interval: float = 0.4,
    debounce_delay: float = 0.3,
) -> None:
    """Entry point for watch mode."""
    target = target_path or Path.cwd()
    watcher = FileWatcher(
        target_path=target,
        poll_interval=poll_interval,
        debounce_delay=debounce_delay,
    )
    watcher.run(max_iterations=max_iterations)
