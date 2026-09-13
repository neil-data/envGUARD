"""Interactive Terminal UI and Dashboard for EnvGuard v0.2.5."""

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

from envguard.baseline import create_baseline, load_baseline
from envguard.config import load_config
from envguard.env_diff import compare_env_files
from envguard.git_handler import (
    get_repo_root,
    get_staged_files,
    is_env_tracked,
    is_git_repo,
    run_git_command,
)
from envguard.diagnostics import run_diagnostics
from envguard.hook import install_pre_commit_hook, is_hook_installed
from envguard.initializer import init_project
from envguard.patterns import load_default_patterns
from envguard.reporter import (
    console,
    print_blocked_commit,
    print_check_passed,
    print_diagnostics,
    print_diff_report,
    print_hook_installed,
    print_init_result,
    print_rule_explanation,
    print_rules_list,
    print_scan_findings,
    print_status_dashboard,
)
from envguard.scanner import scan_directory, scan_staged
from envguard.theme import (
    create_header_panel,
    create_project_context_table,
    create_success_panel,
)

BANNER = create_header_panel()


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

    config_file = repo_root / ".envguard.yml"
    config_status = "[green]VALID (.envguard.yml)[/green]" if config_file.is_file() else "[dim]DEFAULT[/dim]"

    baseline_file = repo_root / ".envguard-baseline.json"
    baseline_status = None
    if baseline_file.is_file():
        try:
            b_data = load_baseline(baseline_file)
            baseline_status = f"[green]ACTIVE ({len(b_data.fingerprints)} entries)[/green]"
        except Exception:
            baseline_status = "[yellow]INVALID[/yellow]"

    print_status_dashboard(
        is_git=is_git,
        env_tracked=env_tracked,
        findings=findings,
        diff_result=diff_result,
        diff_error=diff_error,
        hook_installed=hook_installed,
        config_status=config_status,
        baseline_status=baseline_status,
    )


def run_scan_action(cwd: Path) -> None:
    """Execute full working directory scan using core modules."""
    console.print(f"\n[bold cyan]▶ Scanning working directory ({cwd})...[/bold cyan]\n")
    config = load_config(root_dir=cwd)
    patterns = load_default_patterns(
        disabled_rules=config.disabled_rules,
        severity_overrides=config.severity_overrides,
    )
    stats = {"files_scanned": 0, "files_skipped": 0}
    with console.status("[bold cyan]Scanning project files for secrets...[/bold cyan]", spinner="dots"):
        findings = scan_directory(
            cwd,
            patterns=patterns,
            respect_gitignore=True,
            exclude_patterns=config.exclude,
            max_file_size_bytes=config.max_file_size_bytes,
            stats=stats,
        )
    print_scan_findings(findings, title=f"Scan Report: {cwd.name}", stats=stats)


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
        print_check_passed(no_staged=True)
        return

    patterns = load_default_patterns(
        disabled_rules=config.disabled_rules,
        severity_overrides=config.severity_overrides,
    )

    findings = scan_staged(
        repo_path=repo_root,
        patterns=patterns,
        max_file_size_bytes=config.max_file_size_bytes,
        exclude_patterns=config.exclude,
    )

    blocking = [f for f in findings if f.is_blocking]
    low_findings = [f for f in findings if not f.is_blocking]

    if blocking:
        print_blocked_commit(blocking)
    else:
        print_check_passed(low_findings_count=len(low_findings))


def run_diff_action(cwd: Path) -> None:
    """Execute environment file comparison using core modules."""
    console.print("\n[bold cyan]▶ Comparing .env vs .env.example...[/bold cyan]\n")
    env_path = cwd / ".env"
    example_path = cwd / ".env.example"

    if not env_path.is_file() and not example_path.is_file():
        console.print("[yellow]Neither .env nor .env.example found in the current directory.[/yellow]")
        return
    if not env_path.is_file():
        console.print("[bold red]Error:[/bold red] .env file not found.")
        return
    if not example_path.is_file():
        console.print("[bold red]Error:[/bold red] .env.example file not found.")
        return

    try:
        diff_result = compare_env_files(env_path, example_path)
        print_diff_report(diff_result)
    except Exception as e:
        console.print(f"[bold red]Error comparing environment files:[/bold red] {e}")


def run_install_hook_action(cwd: Path) -> None:
    """Execute pre-commit hook installation using core modules."""
    console.print("\n[bold cyan]▶ Installing EnvGuard Git pre-commit hook...[/bold cyan]\n")
    if not is_git_repo(cwd):
        console.print("[bold red]Error:[/bold red] Current directory is not a Git repository.")
        return

    repo_root = get_repo_root(cwd) or cwd
    success, message = install_pre_commit_hook(repo_root)

    if success:
        print_hook_installed(message)
    else:
        console.print(f"[bold red]Failed to install hook:[/bold red] {message}")


def run_baseline_action(cwd: Path) -> None:
    """Create or update baseline file (.envguard-baseline.json) from working directory."""
    console.print("\n[bold cyan]▶ Creating / Updating Security Baseline...[/bold cyan]\n")
    repo_root = get_repo_root(cwd) or cwd
    config = load_config(root_dir=repo_root)
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
    baseline_path = repo_root / ".envguard-baseline.json"
    count = create_baseline(findings=findings, output_path=baseline_path, overwrite=True)
    console.print()
    console.print(
        Panel(
            f"[bold green]BASELINE RECORDED[/bold green]\n\n"
            f"Saved [cyan]{count}[/cyan] fingerprint(s) to [bold]{baseline_path.name}[/bold].\n"
            f"Known findings will now be suppressed during scans when using '--baseline'.",
            border_style="green",
            box=box.ROUNDED,
            expand=False,
            padding=(0, 2),
        )
    )
    console.print()


def run_safe_demo_action() -> None:
    """Execute a safe secret leak simulation in an isolated temporary directory.

    Guaranteed never to modify user repository, staging area, or files.
    """
    console.print()
    console.print(
        Panel(
            Align.center(Text("ENVGUARD DEMO SIMULATION", style="bold cyan")),
            border_style="cyan",
            box=box.ROUNDED,
            expand=False,
            padding=(0, 2),
        )
    )
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
                console.print("[bold red]DEMO RESULT: COMMIT WAS BLOCKED BY ENVGUARD[/bold red]\n")
            else:
                console.print("[yellow]Notice: No secrets flagged in demo.[/yellow]\n")

        except Exception as e:
            console.print(f"[bold red]Demo encountered an issue:[/bold red] {e}\n")
        finally:
            console.print("[green]✓ Demo environment cleaned safely[/green]")


def run_init_action(cwd: Path) -> None:
    """Initialize repository configuration and ignore files."""
    console.print(f"\n[bold cyan]▶ Initializing EnvGuard in {cwd}...[/bold cyan]\n")
    res = init_project(cwd)
    print_init_result(res)


def run_doctor_action(cwd: Path) -> None:
    """Run diagnostics checks."""
    console.print(f"\n[bold cyan]▶ Running EnvGuard Doctor on {cwd}...[/bold cyan]\n")
    report = run_diagnostics(cwd)
    print_diagnostics(report)


def run_rules_action() -> None:
    """List detection rules."""
    console.print("\n[bold cyan]▶ Catalog of EnvGuard Detection Rules...[/bold cyan]\n")
    disabled_rules = set()
    severity_overrides = {}
    try:
        config = load_config()
        disabled_rules = config.disabled_rules
        severity_overrides = config.severity_overrides
    except Exception:
        pass

    patterns = load_default_patterns(
        disabled_rules=disabled_rules,
        severity_overrides=severity_overrides,
    )
    print_rules_list(patterns)


def display_menu_options(cwd: Path) -> None:
    """Render the interactive menu table."""
    is_git = is_git_repo(cwd)
    console.print(create_header_panel())
    console.print()
    console.print(create_project_context_table(cwd, is_git))
    console.print()

    menu_table = Table(show_header=False, box=None, padding=(0, 2))
    menu_table.add_column("Key", style="bold cyan")
    menu_table.add_column("Action", style="white")

    menu_table.add_row("[1]", "Project Security Status")
    menu_table.add_row("[2]", "Scan Working Directory")
    menu_table.add_row("[3]", "Check Staged Git Changes")
    menu_table.add_row("[4]", "Compare .env vs .env.example")
    menu_table.add_row("[5]", "Install Pre-Commit Hook")
    menu_table.add_row("[6]", "Create / Update Baseline")
    menu_table.add_row("[7]", "Run Safe Secret Leak Demo")
    menu_table.add_row("[8]", "Initialize Project (.envguard.yml / .envguardignore)")
    menu_table.add_row("[9]", "Run System Doctor Diagnostics")
    menu_table.add_row("[0]", "Exit")

    console.print(
        Panel(
            menu_table,
            title="[bold]Select an Option[/bold]",
            border_style="blue",
            box=box.ROUNDED,
            expand=False,
        )
    )


def launch_interactive_menu() -> None:
    """Main interactive terminal UI loop."""
    cwd = Path.cwd()

    while True:
        try:
            clear_screen()
            display_menu_options(cwd)
            console.print("\n[bold cyan]Select an option:[/bold cyan] ", end="")
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
                run_baseline_action(cwd)
                pause_prompt()
            elif choice == "7":
                run_safe_demo_action()
                pause_prompt()
            elif choice == "8":
                run_init_action(cwd)
                pause_prompt()
            elif choice == "9":
                run_doctor_action(cwd)
                pause_prompt()
            elif choice in ("0", "q", "exit"):
                console.print("\n[green]Goodbye! Stay safe.[/green]\n")
                sys.exit(0)
            else:
                console.print(f"\n[bold yellow]Invalid option '{choice}'. Please select 0-9.[/bold yellow]")
                pause_prompt()
        except (KeyboardInterrupt, EOFError):
            console.print("\n\n[yellow]Exiting EnvGuard...[/yellow]\n")
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
