"""Click CLI entry points for EnvGuard v0.2.5."""

from pathlib import Path
import sys
import traceback
from typing import Optional
import click

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure standard Exit Code Contract: Invalid CLI usage exits with 3
click.exceptions.UsageError.exit_code = 3
click.exceptions.BadParameter.exit_code = 3
click.exceptions.NoSuchOption.exit_code = 3

from envguard import __version__
from envguard.baseline import (
    DEFAULT_BASELINE_FILENAME,
    create_baseline,
    filter_baseline_findings,
    load_baseline,
)
from envguard.config import load_config
from envguard.env_diff import compare_env_files
from envguard.exceptions import (
    BaselineError,
    ConfigurationError,
    EnvDiffError,
    EnvGuardError,
    GitError,
    HookError,
    ScanError,
)
from envguard.git_handler import (
    get_repo_root,
    get_staged_files,
    is_env_tracked,
    is_git_repo,
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
    render_check_json,
    render_diff_json,
    render_doctor_json,
    render_explain_json,
    render_init_json,
    render_rules_json,
    render_scan_json,
    render_status_json,
)
from envguard.scanner import scan_directory, scan_staged
from envguard.theme import create_error_panel, create_success_panel


def handle_cli_error(e: Exception, verbose: bool = False) -> None:
    """Format user-facing error message with friendly Rich panel unless verbose is requested."""
    title = getattr(e, "title", "EnvGuard Error")
    reason = getattr(e, "reason", None) or str(e)
    suggestion = getattr(e, "suggestion", None)

    if not suggestion:
        if isinstance(e, ConfigurationError) or "configuration" in str(e).lower() or "yaml" in str(e).lower():
            title = "Configuration Error"
            suggestion = "Check your .envguard.yml file for syntax and valid schema options."
        elif isinstance(e, GitError) or "git" in str(e).lower():
            title = "Git Repository Error"
            suggestion = "Ensure you are inside a valid Git repository with commits or staged files."
        elif isinstance(e, BaselineError) or "baseline" in str(e).lower():
            title = "Baseline Error"
            suggestion = "Verify your .envguard-baseline.json file exists and contains valid JSON."
        elif isinstance(e, FileNotFoundError):
            title = "File Not Found"
            suggestion = "Check that the specified target path exists and is accessible."
        else:
            suggestion = "Run the command with --verbose for additional diagnostic details."

    console.print()
    console.print(create_error_panel(title=title, reason=reason, suggestion=suggestion, verbose_hint=not verbose))
    console.print()

    if verbose:
        traceback.print_exc()


@click.group(invoke_without_command=True)
@click.version_option(version=__version__, prog_name="EnvGuard", message="EnvGuard version %(version)s")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose diagnostics.")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """EnvGuard - A Developer-Side Safety Gate for Secrets and Environment Drift."""
    ctx.ensure_object(dict)
    ctx.obj["VERBOSE"] = verbose

    if ctx.invoked_subcommand is None:
        from envguard.interactive import launch_interactive_menu
        launch_interactive_menu()


@main.command(name="menu")
def menu_cmd() -> None:
    """Launch the interactive EnvGuard security dashboard in the current terminal."""
    from envguard.interactive import launch_interactive_menu
    launch_interactive_menu()


@main.command(name="ui")
def ui_cmd() -> None:
    """Launch the EnvGuard security console in a dedicated separate terminal window."""
    from envguard.interactive import launch_separate_terminal
    launch_separate_terminal()


@main.command(name="scan")
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True, file_okay=True, dir_okay=True, path_type=Path),
    default=".",
    help="Target directory or file to scan (defaults to current directory).",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    help="Output format: text (default) or machine-readable json.",
)
@click.option(
    "--baseline",
    "-b",
    "baseline_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to baseline file (.envguard-baseline.json).",
)
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose diagnostics.")
@click.pass_context
def scan_cmd(ctx: click.Context, path: Path, output_format: str, baseline_path: Optional[Path], verbose: bool) -> None:
    """Scan the working directory recursively for secrets, respecting .gitignore and config."""
    is_verbose = verbose or ctx.obj.get("VERBOSE", False)
    target = path.resolve()
    target_dir = target if target.is_dir() else target.parent

    try:
        config = load_config(root_dir=target_dir)

        if is_verbose and config.warnings:
            for w in config.warnings:
                console.print(f"[yellow]Config warning:[/yellow] {w}", file=sys.stderr)

        patterns = load_default_patterns(
            disabled_rules=config.disabled_rules,
            severity_overrides=config.severity_overrides,
        )

        verbose_log = [] if is_verbose else None
        stats = {"files_scanned": 0, "files_skipped": 0}

        if target.is_file():
            from envguard.scanner import scan_file_streaming
            findings, skip_reason = scan_file_streaming(
                file_path=target,
                rel_path_str=target.name,
                patterns=patterns,
                max_file_size_bytes=config.max_file_size_bytes,
            )
            if skip_reason:
                stats["files_skipped"] = 1
                if is_verbose:
                    console.print(f"[dim]Skipped file ({skip_reason}): {target.name}[/dim]")
            else:
                stats["files_scanned"] = 1
        else:
            if output_format.lower() == "json":
                findings = scan_directory(
                    directory=target,
                    patterns=patterns,
                    respect_gitignore=True,
                    exclude_patterns=config.exclude,
                    max_file_size_bytes=config.max_file_size_bytes,
                    verbose_log=verbose_log,
                    stats=stats,
                )
            else:
                with console.status("[bold cyan]Scanning project files for secrets...[/bold cyan]", spinner="dots"):
                    findings = scan_directory(
                        directory=target,
                        patterns=patterns,
                        respect_gitignore=True,
                        exclude_patterns=config.exclude,
                        max_file_size_bytes=config.max_file_size_bytes,
                        verbose_log=verbose_log,
                        stats=stats,
                    )

        if is_verbose and verbose_log:
            for log_entry in verbose_log:
                console.print(f"[dim]{log_entry}[/dim]")

        # Baseline resolution
        resolved_baseline = baseline_path
        if not resolved_baseline:
            candidate = target_dir / DEFAULT_BASELINE_FILENAME
            if candidate.is_file():
                resolved_baseline = candidate

        baseline_fingerprints = load_baseline(resolved_baseline) if resolved_baseline else set()
        new_findings, suppressed_findings = filter_baseline_findings(findings, baseline_fingerprints)

        if output_format.lower() == "json":
            render_scan_json(
                findings=new_findings,
                command="scan",
                suppressed_count=len(suppressed_findings),
            )
        else:
            if suppressed_findings:
                console.print(f"[dim]Suppressed {len(suppressed_findings)} finding(s) matching baseline.[/dim]\n")
            print_scan_findings(new_findings, title=f"Scan Report: {target.name}", stats=stats)

        if new_findings:
            sys.exit(1)
        sys.exit(0)
    except EnvGuardError as e:
        handle_cli_error(e, verbose=is_verbose)
        sys.exit(2)
    except Exception as e:
        handle_cli_error(e, verbose=is_verbose)
        sys.exit(2)


@main.command(name="check")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    help="Output format: text (default) or machine-readable json.",
)
@click.option(
    "--baseline",
    "-b",
    "baseline_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to baseline file (.envguard-baseline.json).",
)
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose diagnostics.")
@click.pass_context
def check_cmd(ctx: click.Context, output_format: str, baseline_path: Optional[Path], verbose: bool) -> None:
    """Scan staged Git content before commit. Configured block_on severities block."""
    is_verbose = verbose or ctx.obj.get("VERBOSE", False)
    cwd = Path.cwd()

    if not is_git_repo(cwd):
        err_msg = "Current directory is not a Git repository."
        if output_format.lower() == "json":
            render_diff_json(None, error=err_msg)
        else:
            handle_cli_error(GitError(err_msg), verbose=is_verbose)
        sys.exit(2)

    try:
        repo_root = get_repo_root(cwd) or cwd
        config = load_config(root_dir=repo_root)

        if is_verbose and config.warnings:
            for w in config.warnings:
                console.print(f"[yellow]Config warning:[/yellow] {w}", file=sys.stderr)

        staged_files = get_staged_files(repo_root)

        if not staged_files:
            if output_format.lower() == "json":
                render_check_json(blocking_findings=[], low_findings=[], no_staged=True)
            else:
                print_check_passed(no_staged=True)
            sys.exit(0)

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

        # Baseline resolution
        resolved_baseline = baseline_path
        if not resolved_baseline:
            candidate = repo_root / DEFAULT_BASELINE_FILENAME
            if candidate.is_file():
                resolved_baseline = candidate

        baseline_fingerprints = load_baseline(resolved_baseline) if resolved_baseline else set()
        new_findings, suppressed_findings = filter_baseline_findings(findings, baseline_fingerprints)

        blocking_findings = [f for f in new_findings if f.is_blocking]
        low_findings = [f for f in new_findings if not f.is_blocking]

        if output_format.lower() == "json":
            render_check_json(
                blocking_findings=blocking_findings,
                low_findings=low_findings,
                no_staged=False,
            )
        else:
            if suppressed_findings:
                console.print(f"[dim]Suppressed {len(suppressed_findings)} staged finding(s) matching baseline.[/dim]\n")

            if blocking_findings:
                print_blocked_commit(blocking_findings)
            else:
                print_check_passed(low_findings_count=len(low_findings))

        if blocking_findings:
            sys.exit(1)
        sys.exit(0)
    except EnvGuardError as e:
        handle_cli_error(e, verbose=is_verbose)
        sys.exit(2)
    except Exception as e:
        handle_cli_error(e, verbose=is_verbose)
        sys.exit(2)


@main.command(name="diff")
@click.option(
    "--env",
    "env_path",
    type=click.Path(path_type=Path),
    default=Path(".env"),
    help="Path to .env file (defaults to .env).",
)
@click.option(
    "--example",
    "example_path",
    type=click.Path(path_type=Path),
    default=Path(".env.example"),
    help="Path to .env.example file (defaults to .env.example).",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    help="Output format: text (default) or machine-readable json.",
)
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose diagnostics.")
@click.pass_context
def diff_cmd(ctx: click.Context, env_path: Path, example_path: Path, output_format: str, verbose: bool) -> None:
    """Detect key drift between .env and .env.example (keys only, no values exposed)."""
    is_verbose = verbose or ctx.obj.get("VERBOSE", False)
    env_file = env_path.resolve()
    example_file = example_path.resolve()

    missing_files = []
    if not env_file.is_file():
        missing_files.append(str(env_path))
    if not example_file.is_file():
        missing_files.append(str(example_path))

    if missing_files:
        err_msg = f"Required file(s) not found: {', '.join(missing_files)}"
        if output_format.lower() == "json":
            render_diff_json(None, error=err_msg)
        else:
            handle_cli_error(FileNotFoundError(err_msg), verbose=is_verbose)
        sys.exit(2)

    try:
        diff_result = compare_env_files(env_file, example_file)
        if output_format.lower() == "json":
            render_diff_json(diff_result)
        else:
            print_diff_report(diff_result)

        if diff_result.has_drift:
            sys.exit(1)
        sys.exit(0)
    except EnvGuardError as e:
        handle_cli_error(e, verbose=is_verbose)
        sys.exit(2)
    except Exception as e:
        handle_cli_error(e, verbose=is_verbose)
        sys.exit(2)


@main.command(name="status")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    help="Output format: text (default) or machine-readable json.",
)
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose diagnostics.")
@click.pass_context
def status_cmd(ctx: click.Context, output_format: str, verbose: bool) -> None:
    """Show a comprehensive project security status report."""
    is_verbose = verbose or ctx.obj.get("VERBOSE", False)
    cwd = Path.cwd()
    is_git = is_git_repo(cwd)
    repo_root = get_repo_root(cwd) or cwd

    try:
        config = load_config(root_dir=repo_root)

        # 1. Check .env tracked
        env_tracked = is_git and is_env_tracked(repo_root)

        # 2. Check secrets in working directory
        patterns = load_default_patterns(
            disabled_rules=config.disabled_rules,
            severity_overrides=config.severity_overrides,
        )
        findings = scan_directory(
            directory=cwd,
            patterns=patterns,
            respect_gitignore=True,
            exclude_patterns=config.exclude,
            max_file_size_bytes=config.max_file_size_bytes,
        )

        # 3. Check .env vs .env.example
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

        # 4. Check pre-commit hook
        hook_installed = is_git and is_hook_installed(repo_root)

        # 5. Configuration & Baseline status
        baseline_file = repo_root / DEFAULT_BASELINE_FILENAME
        baseline_status = None
        if baseline_file.is_file():
            try:
                b_data = load_baseline(baseline_file)
                baseline_status = f"[green]ACTIVE ({len(b_data.fingerprints)} entries)[/green]"
            except Exception:
                baseline_status = "[yellow]INVALID[/yellow]"

        config_file = repo_root / ".envguard.yml"
        config_status = "[green]VALID (.envguard.yml)[/green]" if config_file.is_file() else "[dim]DEFAULT[/dim]"

        if output_format.lower() == "json":
            # Compute status
            high = sum(1 for f in findings if f.severity == "HIGH")
            med = sum(1 for f in findings if f.severity == "MEDIUM")
            has_drift = diff_result is not None and diff_result.has_drift
            if env_tracked or high > 0:
                overall_status = "CRITICAL"
            elif med > 0 or has_drift or not hook_installed:
                overall_status = "ATTENTION REQUIRED"
            elif len(findings) > 0:
                overall_status = "WARNING"
            else:
                overall_status = "SECURE"

            render_status_json(
                is_git=is_git,
                env_tracked=env_tracked,
                findings=findings,
                diff_result=diff_result,
                hook_installed=hook_installed,
                overall_status=overall_status,
            )
        else:
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
        sys.exit(0)
    except EnvGuardError as e:
        handle_cli_error(e, verbose=is_verbose)
        sys.exit(2)
    except Exception as e:
        handle_cli_error(e, verbose=is_verbose)
        sys.exit(2)


@main.command(name="install-hook")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose diagnostics.")
@click.pass_context
def install_hook_cmd(ctx: click.Context, verbose: bool) -> None:
    """Install or update the EnvGuard Git pre-commit hook."""
    is_verbose = verbose or ctx.obj.get("VERBOSE", False)
    cwd = Path.cwd()
    if not is_git_repo(cwd):
        handle_cli_error(GitError("Current directory is not a Git repository."), verbose=is_verbose)
        sys.exit(2)

    try:
        repo_root = get_repo_root(cwd) or cwd
        success, message = install_pre_commit_hook(repo_root)

        if success:
            print_hook_installed(message)
            sys.exit(0)
        else:
            handle_cli_error(HookError(f"Failed to install hook: {message}"), verbose=is_verbose)
            sys.exit(2)
    except EnvGuardError as e:
        handle_cli_error(e, verbose=is_verbose)
        sys.exit(2)
    except Exception as e:
        handle_cli_error(e, verbose=is_verbose)
        sys.exit(2)


# Baseline sub-group
@main.group(name="baseline")
def baseline_group() -> None:
    """Manage EnvGuard baseline files (.envguard-baseline.json)."""
    pass


@baseline_group.command(name="create")
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    default=".",
    help="Target directory to scan for baseline (defaults to current directory).",
)
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(path_type=Path),
    default=Path(DEFAULT_BASELINE_FILENAME),
    help="Output baseline file path (defaults to .envguard-baseline.json).",
)
@click.option(
    "--overwrite",
    is_flag=True,
    help="Overwrite existing baseline file without confirmation.",
)
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose diagnostics.")
@click.pass_context
def baseline_create_cmd(ctx: click.Context, path: Path, output_path: Path, overwrite: bool, verbose: bool) -> None:
    """Create a new baseline from current findings. Never stores raw secrets."""
    is_verbose = verbose or ctx.obj.get("VERBOSE", False)
    target_dir = path.resolve()
    resolved_output = output_path.resolve() if output_path.is_absolute() else (target_dir / output_path)

    try:
        config = load_config(root_dir=target_dir)
        patterns = load_default_patterns(
            disabled_rules=config.disabled_rules,
            severity_overrides=config.severity_overrides,
        )

        findings = scan_directory(
            directory=target_dir,
            patterns=patterns,
            respect_gitignore=True,
            exclude_patterns=config.exclude,
            max_file_size_bytes=config.max_file_size_bytes,
        )

        captured_count = create_baseline(
            findings=findings,
            output_path=resolved_output,
            overwrite=overwrite,
        )

        console.print()
        console.print(
            create_success_panel(
                "BASELINE CREATED",
                f"Captured [cyan]{captured_count}[/cyan] secret fingerprint(s) in [bold]{resolved_output.name}[/bold].\n"
                f"[dim]Existing findings will now be suppressed during scans when using --baseline.[/dim]",
            )
        )
        console.print()
        sys.exit(0)
    except EnvGuardError as e:
        handle_cli_error(e, verbose=is_verbose)
        sys.exit(2)
    except Exception as e:
        handle_cli_error(e, verbose=is_verbose)
        sys.exit(2)



@main.command(name="init")
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    default=".",
    help="Target repository directory (defaults to current directory).",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default=None,
    help="Output format: 'text' (default) or 'json'.",
)
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose diagnostics.")
@click.pass_context
def init_cmd(ctx: click.Context, path: Path, output_format: Optional[str], verbose: bool) -> None:
    """Initialize EnvGuard configuration (.envguard.yml) and ignore file (.envguardignore)."""
    is_verbose = verbose or ctx.obj.get("VERBOSE", False)
    target_format = (output_format or ctx.obj.get("FORMAT", "text")).lower()
    target_dir = path.resolve()

    try:
        result = init_project(target_dir)
        if target_format == "json":
            render_init_json(result)
        else:
            print_init_result(result)
        sys.exit(0)
    except EnvGuardError as e:
        handle_cli_error(e, verbose=is_verbose)
        sys.exit(2)
    except Exception as e:
        handle_cli_error(e, verbose=is_verbose)
        sys.exit(2)


@main.command(name="doctor")
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    default=".",
    help="Target repository directory (defaults to current directory).",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default=None,
    help="Output format: 'text' (default) or 'json'.",
)
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose diagnostics.")
@click.pass_context
def doctor_cmd(ctx: click.Context, path: Path, output_format: Optional[str], verbose: bool) -> None:
    """Diagnose EnvGuard environment, configuration, tools, and hooks."""
    is_verbose = verbose or ctx.obj.get("VERBOSE", False)
    target_format = (output_format or ctx.obj.get("FORMAT", "text")).lower()
    target_dir = path.resolve()

    try:
        report = run_diagnostics(target_dir)
        if target_format == "json":
            render_doctor_json(report)
        else:
            print_diagnostics(report)

        if report.overall_status == "ERROR":
            sys.exit(1)
        sys.exit(0)
    except EnvGuardError as e:
        handle_cli_error(e, verbose=is_verbose)
        sys.exit(2)
    except Exception as e:
        handle_cli_error(e, verbose=is_verbose)
        sys.exit(2)


@main.command(name="explain")
@click.argument("rule_id", required=True)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default=None,
    help="Output format: 'text' (default) or 'json'.",
)
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose diagnostics.")
@click.pass_context
def explain_cmd(ctx: click.Context, rule_id: str, output_format: Optional[str], verbose: bool) -> None:
    """Explain why a detection rule exists, its severity, and remediation guidance."""
    is_verbose = verbose or ctx.obj.get("VERBOSE", False)
    target_format = (output_format or ctx.obj.get("FORMAT", "text")).lower()

    try:
        patterns = load_default_patterns()
        clean_id = rule_id.strip().lower()
        matched_pattern = next((p for p in patterns if p.id.lower() == clean_id), None)

        if not matched_pattern:
            if target_format == "json":
                render_check_json([], [])  # Or error
            console.print()
            console.print(create_error_panel("UNKNOWN RULE", f"Rule ID '{rule_id}' was not found in registered rules.\nRun 'envguard rules list' to see all rules."))
            console.print()
            sys.exit(3)

        if target_format == "json":
            render_explain_json(matched_pattern)
        else:
            print_rule_explanation(matched_pattern)
        sys.exit(0)
    except EnvGuardError as e:
        handle_cli_error(e, verbose=is_verbose)
        sys.exit(2)
    except Exception as e:
        handle_cli_error(e, verbose=is_verbose)
        sys.exit(2)


@main.group(name="rules")
def rules_group() -> None:
    """Inspect and list EnvGuard detection rules."""
    pass


@rules_group.command(name="list")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default=None,
    help="Output format: 'text' (default) or 'json'.",
)
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose diagnostics.")
@click.pass_context
def rules_list_cmd(ctx: click.Context, output_format: Optional[str], verbose: bool) -> None:
    """List all available EnvGuard detection rules."""
    is_verbose = verbose or ctx.obj.get("VERBOSE", False)
    target_format = (output_format or ctx.obj.get("FORMAT", "text")).lower()

    try:
        config = load_config()
        patterns = load_default_patterns(
            disabled_rules=config.disabled_rules,
            severity_overrides=config.severity_overrides,
        )
        if target_format == "json":
            render_rules_json(patterns)
        else:
            print_rules_list(patterns)
        sys.exit(0)
    except EnvGuardError as e:
        handle_cli_error(e, verbose=is_verbose)
        sys.exit(2)
    except Exception as e:
        handle_cli_error(e, verbose=is_verbose)
        sys.exit(2)


if __name__ == "__main__":
    main()
