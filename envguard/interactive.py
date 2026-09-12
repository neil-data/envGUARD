"""Interactive Terminal UI and Dashboard for EnvGuard."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Optional

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from envguard.config import load_config
from envguard.env_diff import compare_env_files
from envguard.git_handler import (
    get_repo_root,
    get_staged_files,
    is_env_tracked,
    is_git_repo,
    run_git_command,
)
from envguard.hook import install_pre_commit_hook, is_hook_installed
from envguard.patterns import load_default_patterns
from envguard.reporter import (
    console,
    print_blocked_commit,
    print_diff_report,
    print_scan_findings,
    print_status_dashboard,
)
from envguard.scanner import scan_directory, scan_staged

ASCII_LOGO = """\
[bold green]███████╗███╗   ██╗██╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
██╔════╝████╗  ██║██║   ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
█████╗  ██╔██╗ ██║██║   ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██╔══╝  ██║╚██╗██║╚██╗ ██╔╝██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
███████╗██║ ╚████║ ╚████╔╝ ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚══════╝╚═╝  ╚═══╝  ╚═══╝   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝[/bold green]"""

SUBTITLE = "[bold white]Developer-Side Safety Gate for Secrets & Drift[/bold white]"


def get_banner_panel() -> Panel:
    """Return the styled EnvGuard logo and tagline inside a clean double box."""
    content = Group(
        Align.center(ASCII_LOGO),
        Text(""),
        Align.center(SUBTITLE),
    )
    return Panel(content, border_style="cyan", box=box.DOUBLE, expand=False)


BANNER = get_banner_panel()


def clear_screen() -> None:
    """Clear the terminal screen cleanly across OS platforms."""
    os.system("cls" if os.name == "nt" else "clear")


def pause_prompt() -> None:
    """Pause execution until the user presses Enter."""
    console.print("\n[dim]Press Enter to return to the menu...[/dim]", end="")
    try:
        input()
    except (KeyboardInterrupt, EOFError):
        pass


def run_status_action(cwd: Path) -> None:
    """Execute status check using core modules."""
    console.print("\n[bold cyan]▶ Checking Project Security Status...[/bold cyan]")
    is_git = is_git_repo(cwd)
    repo_root = get_repo_root(cwd) or cwd
    config = load_config(root_dir=repo_root)

    env_tracked = is_git and is_env_tracked(repo_root)
    patterns = load_default_patterns(
        disabled_rules=config.disabled_rules,
        severity_overrides=config.severity_overrides,
    )
    findings = scan_directory(
        cwd,
        patterns=patterns,
        respect_gitignore=True,
        exclude_patterns=config.exclude,
        max_file_size_bytes=config.max_file_size_bytes,
    )

    env_file = cwd / ".env"
    example_file = cwd / ".env.example"
    diff_result = None
    diff_error = None

    if env_file.is_file() and example_file.is_file():
        try:
            diff_result = compare_env_files(env_file, example_file)
        except Exception as e:
            diff_error = f"Error: {e}"
    elif not env_file.is_file() and not example_file.is_file():
        diff_error = "No .env or .env.example found"
    elif not env_file.is_file():
        diff_error = ".env missing"
    else:
        diff_error = ".env.example missing"

    hook_installed = is_git and is_hook_installed(repo_root)

    print_status_dashboard(
        is_git=is_git,
        env_tracked=env_tracked,
        findings=findings,
        diff_result=diff_result,
        diff_error=diff_error,
        hook_installed=hook_installed,
    )


def run_scan_action(cwd: Path) -> None:
    """Execute full working directory scan using core modules."""
    console.print(f"\n[bold cyan]▶ Scanning working directory ({cwd})...[/bold cyan]\n")
    config = load_config(root_dir=cwd)
    patterns = load_default_patterns(
        disabled_rules=config.disabled_rules,
        severity_overrides=config.severity_overrides,
    )
    findings = scan_directory(
        cwd,
        patterns=patterns,
        respect_gitignore=True,
        exclude_patterns=config.exclude,
        max_file_size_bytes=config.max_file_size_bytes,
    )
    print_scan_findings(findings, title=f"Scan Report: {cwd.name}")


def run_check_action(cwd: Path) -> None:
    """Execute staged Git content check using core modules."""
    console.print("\n[bold cyan]▶ Checking staged Git changes...[/bold cyan]\n")
    if not is_git_repo(cwd):
        console.print("[bold red]Error:[/bold red] Current directory is not a Git repository.")
        return

    repo_root = get_repo_root(cwd) or cwd
    config = load_config(root_dir=repo_root)
    staged_files = get_staged_files(repo_root)

    if not staged_files:
        console.print("[green]✓ No staged files to scan.[/green]")
        return

    patterns = load_default_patterns(
        disabled_rules=config.disabled_rules,
        severity_overrides=config.severity_overrides,
    )
    findings = scan_staged(
        repo_root,
        patterns=patterns,
        max_file_size_bytes=config.max_file_size_bytes,
    )

    blocking_findings = [f for f in findings if f.is_blocking_for(config.block_on)]
    low_findings = [f for f in findings if not f.is_blocking_for(config.block_on)]

    if blocking_findings:
        print_blocked_commit(blocking_findings)
        if low_findings:
            console.print(f"[yellow]Note: Also detected {len(low_findings)} non-blocking warning(s).[/yellow]\n")
    elif low_findings:
        console.print("[yellow]⚠ Low-confidence warnings detected in staged content (non-blocking):[/yellow]")
        print_scan_findings(low_findings, title="Staged Content Warnings")
        console.print("[green]✓ Staged content passed security gate.[/green]")
    else:
        console.print("[green]✓ Staged content clean. No secrets detected.[/green]")


def run_diff_action(cwd: Path) -> None:
    """Execute .env vs .env.example drift check using core modules."""
    console.print("\n[bold cyan]▶ Comparing .env and .env.example...[/bold cyan]")
    env_file = cwd / ".env"
    example_file = cwd / ".env.example"

    missing_files = []
    if not env_file.is_file():
        missing_files.append(".env")
    if not example_file.is_file():
        missing_files.append(".env.example")

    if missing_files:
        console.print(f"[bold yellow]Note:[/bold yellow] Required file(s) not found in current directory: {', '.join(missing_files)}")
        return

    try:
        diff_result = compare_env_files(env_file, example_file)
        print_diff_report(diff_result)
    except Exception as e:
        console.print(f"[bold red]Error parsing files:[/bold red] {e}")


def run_install_hook_action(cwd: Path) -> None:
    """Execute pre-commit hook installation using core modules."""
    console.print("\n[bold cyan]▶ Installing EnvGuard Git pre-commit hook...[/bold cyan]\n")
    if not is_git_repo(cwd):
        console.print("[bold red]Error:[/bold red] Current directory is not a Git repository.")
        return

    repo_root = get_repo_root(cwd) or cwd
    success, message = install_pre_commit_hook(repo_root)

    if success:
        console.print(f"[green]✓ {message}[/green]")
        console.print(
            "\n[bold]Your staged changes will now be checked for secrets before every commit.[/bold]\n"
            "[dim]Note: Ensure 'envguard' is accessible in your system PATH.[/dim]"
        )
    else:
        console.print(f"[bold red]Failed to install hook:[/bold red] {message}")


def run_safe_demo_action() -> None:
    """Execute a safe secret leak simulation in an isolated temporary directory.

    Guaranteed never to modify user repository, staging area, or files.
    """
    console.print()
    console.print(Panel(Align.center("[bold cyan]ENVGUARD DEMO[/bold cyan]"), border_style="cyan", box=box.DOUBLE, expand=False))
    console.print()

    with tempfile.TemporaryDirectory() as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        try:
            # 1. Initialize temporary Git repository
            run_git_command(["init"], cwd=temp_dir, check=True)
            console.print("[green]✓ Temporary repository created[/green]")

            # 2. Create fake secret test file
            fake_secret_key = "".join(["AK", "IA", "IOSFODNN7", "EXAMPLE"])
            var_name = "AWS_" + "ACCESS_KEY_ID"
            secret_file = temp_dir / "cloud_config.py"
            secret_file.write_text(
                f'# Cloud Provider Settings\n{var_name} = "{fake_secret_key}"\n',
                encoding="utf-8",
            )
            console.print("[green]✓ Fake secret introduced[/green]")

            # 3. Stage the file
            run_git_command(["add", "cloud_config.py"], cwd=temp_dir, check=True)
            console.print("[green]✓ File staged[/green]\n")

            # 4. Run EnvGuard staged content scan directly
            patterns = load_default_patterns()
            findings = scan_staged(temp_dir, patterns=patterns)
            blocking_findings = [f for f in findings if f.is_blocking]

            if blocking_findings:
                print_blocked_commit(blocking_findings)
                console.print("[bold red]COMMIT WOULD BE BLOCKED[/bold red]\n")
            else:
                console.print("[yellow]Notice: No secrets flagged in demo.[/yellow]\n")

        except Exception as e:
            console.print(f"[bold red]Demo encountered an issue:[/bold red] {e}\n")
        finally:
            console.print("[green]✓ Demo environment cleaned safely[/green]")


def display_menu_options(cwd: Path) -> None:
    """Render the interactive menu table."""
    console.print(BANNER)
    console.print(f"[bold]Active Workspace:[/bold] [cyan]{cwd}[/cyan]\n")

    menu_table = Table(show_header=False, box=None, padding=(0, 2))
    menu_table.add_column("Key", style="bold cyan")
    menu_table.add_column("Action", style="white")

    menu_table.add_row("[1]", "📊 Project Security Status")
    menu_table.add_row("[2]", "🔍 Scan Working Directory for Secrets")
    menu_table.add_row("[3]", "🛑 Check Staged Git Changes (Pre-commit gate)")
    menu_table.add_row("[4]", "🔄 Compare .env vs .env.example Drift")
    menu_table.add_row("[5]", "🪝 Install / Update Git Pre-Commit Hook")
    menu_table.add_row("[6]", "🧪 Run Safe Secret Leak Demo")
    menu_table.add_row("[0]", "🚪 Exit")

    console.print(Panel(menu_table, title="[bold]Select an Option[/bold]", border_style="blue", expand=False))


def launch_interactive_menu() -> None:
    """Main interactive terminal UI loop."""
    cwd = Path.cwd()

    while True:
        try:
            clear_screen()
            display_menu_options(cwd)
            console.print("\n[bold cyan]EnvGuard>[/bold cyan] ", end="")
            choice = input().strip()

            if choice == "1":
                run_status_action(cwd)
                pause_prompt()
            elif choice == "2":
                run_scan_action(cwd)
                pause_prompt()
            elif choice == "3":
                run_check_action(cwd)
                pause_prompt()
            elif choice == "4":
                run_diff_action(cwd)
                pause_prompt()
            elif choice == "5":
                run_install_hook_action(cwd)
                pause_prompt()
            elif choice == "6":
                run_safe_demo_action()
                pause_prompt()
            elif choice in ("0", "q", "exit"):
                console.print("\n[green]Goodbye! Stay safe.[/green]")
                sys.exit(0)
            else:
                console.print(f"\n[bold yellow]Invalid option '{choice}'. Please select 0-6.[/bold yellow]")
                pause_prompt()
        except (KeyboardInterrupt, EOFError):
            console.print("\n\n[yellow]Exiting EnvGuard...[/yellow]")
            sys.exit(0)


def launch_separate_terminal(cwd: Optional[Path] = None) -> None:
    """Launch a dedicated EnvGuard terminal window where supported."""
    target_dir = cwd or Path.cwd()

    if sys.platform != "win32":
        console.print("[yellow]Note: Dedicated terminal window launching is currently Windows-focused.[/yellow]")
        console.print("[dim]Falling back to launching interactive menu in the current terminal...[/dim]\n")
        launch_interactive_menu()
        return

    # Check for Windows Terminal (wt.exe)
    wt_path = shutil.which("wt.exe") or shutil.which("wt")

    if wt_path:
        console.print("[green]✓ Launching in Windows Terminal...[/green]")
        cmd_args = [
            wt_path,
            "-d",
            str(target_dir),
            "--title",
            "EnvGuard Security Console",
            sys.executable,
            "-m",
            "envguard.cli",
            "menu",
        ]
        try:
            subprocess.Popen(cmd_args)
            console.print("[green]EnvGuard Security Console opened in Windows Terminal.[/green]")
            return
        except Exception as e:
            console.print(f"[yellow]Failed to launch via Windows Terminal ({e}). Falling back to CMD...[/yellow]")

    # Fallback to cmd.exe with a new console
    cmd_fallback = [
        "cmd.exe",
        "/c",
        "start",
        "EnvGuard Security Console",
        "/D",
        str(target_dir),
        "cmd.exe",
        "/k",
        f'"{sys.executable}" -m envguard.cli menu',
    ]
    try:
        subprocess.Popen(cmd_fallback, shell=True)
        console.print("[green]EnvGuard Security Console opened in new CMD window.[/green]")
    except Exception as e:
        console.print(f"[bold red]Could not open separate terminal window:[/bold red] {e}")
        console.print("[dim]Launching interactive menu in current terminal instead...[/dim]\n")
        launch_interactive_menu()
