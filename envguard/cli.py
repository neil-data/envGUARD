"""Click CLI entry points for EnvGuard v0.3.1."""

from pathlib import Path
import sys
import traceback
from typing import Optional
import click
from rich.panel import Panel
from rich import box

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
    inspect_baseline,
    load_baseline,
)
from envguard.ci import detect_ci_environment
from envguard.config import find_config_file, find_org_config_file, load_config
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
from envguard.git_utils import (
    get_changed_files,
    get_default_base_branch,
    get_git_root as get_git_root_util,
    is_git_repository,
)
from envguard.github_actions import write_github_annotations, write_github_job_summary
from envguard.diagnostics import run_diagnostics
from envguard.hook import install_pre_commit_hook, is_hook_installed
from envguard.initializer import init_project
from envguard.multi_repo import parse_repo_targets, scan_multiple_repositories
from envguard.patterns import load_default_patterns
from envguard.reporter import (
    console,
    err_console,
    print_blocked_commit,
    print_check_passed,
    print_diagnostics,
    print_diff_report,
    print_hook_installed,
    print_init_result,
    print_multi_repo_summary,
    print_rule_explanation,
    print_rules_list,
    print_scan_findings,
    print_status_dashboard,
    render_check_json,
    render_ci_summary,
    render_diff_json,
    render_doctor_json,
    render_explain_json,
    render_init_json,
    render_multi_repo_json,
    render_rules_json,
    render_sarif,
    render_scan_json,
    render_status_json,
    write_output,
)
from envguard.scanner import scan_directory, scan_files, scan_staged
from envguard.theme import create_error_panel, create_success_panel


def handle_cli_error(e: Exception, verbose: bool = False, debug: bool = False) -> None:
    """Format user-facing error message with friendly Rich panel without raw traceback."""
    if not debug:
        try:
            ctx = click.get_current_context(silent=True)
            if ctx and ctx.obj:
                debug = ctx.obj.get("DEBUG", False)
        except Exception:
            pass

    if isinstance(e, ConfigurationError):
        title = "ENVGUARD CONFIGURATION ERROR"
        reason = getattr(e, "message", str(e))
        config_path = getattr(e, "config_path", None) or ".envguard.yml"
        field = getattr(e, "field", None)
        expected = getattr(e, "expected", None)
        received = getattr(e, "received", None)
        example = getattr(e, "example", None)

        if verbose:
            parts = [f"[bold]Reason:[/bold]\n{reason}"]
            if config_path:
                parts.append(f"[bold]Configuration file:[/bold]\n{config_path}")
            if field:
                parts.append(f"[bold]Field:[/bold]\n{field}")
            if expected:
                parts.append(f"[bold]Expected:[/bold]\n{expected}")
            if received:
                parts.append(f"[bold]Received:[/bold]\n{received}")
            if example:
                parts.append(f"[bold]Expected format:[/bold]\n{example}")
            suggestion = "Check your configuration file schema and syntax."
            parts.append(f"[bold]Suggestion:[/bold]\n{suggestion}")

            console.print()
            console.print(
                Panel(
                    "\n\n".join(parts),
                    title=f"[bold red]{title}[/bold red]",
                    border_style="red",
                    box=box.ROUNDED,
                    expand=False,
                    padding=(0, 1),
                )
            )
            console.print()
            if debug:
                traceback.print_exc()
            return
        else:
            suggestion = f"Configuration file:\n{config_path}"
            if example:
                suggestion += f"\n\nExpected format:\n{example}"
            else:
                suggestion += "\n\nCheck your .envguard.yml file for syntax and valid schema options."

            console.print()
            console.print(create_error_panel(title=title, reason=reason, suggestion=suggestion, verbose_hint=True))
            console.print()
            if debug:
                traceback.print_exc()
            return

    title = getattr(e, "title", "EnvGuard Error")
    reason = getattr(e, "reason", None) or str(e)
    suggestion = getattr(e, "suggestion", None)

    if not suggestion:
        if isinstance(e, GitError) or "git" in str(e).lower():
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

    if debug or (verbose and not isinstance(e, EnvGuardError)):
        traceback.print_exc()


@click.group(invoke_without_command=True)
@click.version_option(version=__version__, prog_name="EnvGuard", message="EnvGuard version %(version)s")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose diagnostics.")
@click.option("--debug", is_flag=True, help="Enable full traceback debugging.")
@click.pass_context
def main(ctx: click.Context, verbose: bool, debug: bool = False) -> None:
    """EnvGuard - A Developer-Side Safety Gate for Secrets and Environment Drift."""
    ctx.ensure_object(dict)
    ctx.obj["VERBOSE"] = verbose
    ctx.obj["DEBUG"] = debug

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
@click.argument(
    "path_arg",
    required=False,
    type=click.Path(exists=True, file_okay=True, dir_okay=True, path_type=Path),
    default=None,
)
@click.option(
    "--path",
    "-p",
    "path_opt",
    type=click.Path(exists=True, file_okay=True, dir_okay=True, path_type=Path),
    default=None,
    help="Target directory or file to scan (defaults to current directory).",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["text", "json", "sarif"], case_sensitive=False),
    default="text",
    help="Output format: text (default), json, or sarif.",
)
@click.option(
    "--output",
    "-o",
    "output_file",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to write the output report file.",
)
@click.option(
    "--changed",
    is_flag=True,
    help="Scan only files modified relative to a Git base reference.",
)
@click.option(
    "--base",
    default=None,
    help="Base Git reference for --changed comparison (e.g. main, origin/main).",
)
@click.option(
    "--baseline",
    "-b",
    "baseline_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to baseline file (.envguard-baseline.json).",
)
@click.option(
    "--repos",
    "-r",
    "repos",
    multiple=True,
    help="Repository directory (or comma-separated list) to scan in multi-repo mode.",
)
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose diagnostics.")
@click.pass_context
def scan_cmd(
    ctx: click.Context,
    path_arg: Optional[Path],
    path_opt: Optional[Path],
    output_format: str,
    output_file: Optional[Path],
    changed: bool,
    base: Optional[str],
    baseline_path: Optional[Path],
    verbose: bool,
    repos: tuple[str, ...] = (),
) -> None:
    """Scan the working directory recursively for secrets, respecting .gitignore and config."""
    is_verbose = verbose or ctx.obj.get("VERBOSE", False)
    raw_path = path_arg or path_opt or Path(".")
    target = raw_path.resolve()
    target_dir = target if target.is_dir() else target.parent

    try:
        if repos:
            repo_targets = parse_repo_targets(list(repos))
            multi_result = scan_multiple_repositories(
                repo_targets=repo_targets,
                verbose=is_verbose,
            )
            fmt = output_format.lower()
            if fmt == "sarif":
                render_sarif(multi_result.all_findings, output_path=output_file)
            elif fmt == "json":
                render_multi_repo_json(multi_result, output_path=output_file)
            else:
                print_multi_repo_summary(multi_result)
            sys.exit(multi_result.exit_code)

        config = load_config(root_dir=target_dir)

        if is_verbose and config.warnings:
            for w in config.warnings:
                err_console.print(f"[yellow]Config warning:[/yellow] {w}")

        patterns = load_default_patterns(
            disabled_rules=config.disabled_rules,
            severity_overrides=config.severity_overrides,
        )

        verbose_log = [] if is_verbose else None
        stats = {"files_scanned": 0, "files_skipped": 0}

        if changed:
            if base and base.startswith("-"):
                from envguard.exceptions import GitError
                raise GitError(f"Invalid Git reference '{base}': reference cannot begin with '-'")
            findings = scan_directory(
                directory=target,
                patterns=patterns,
                respect_gitignore=True,
                exclude_patterns=config.exclude,
                max_file_size_bytes=config.max_file_size_bytes,
                verbose_log=verbose_log,
                stats=stats,
                advanced_config=config.advanced_detection,
                changed_only=True,
                base_ref=base,
            )
        elif target.is_file():
            from envguard.scanner import scan_file_streaming
            findings, skip_reason = scan_file_streaming(
                file_path=target,
                rel_path_str=target.name,
                patterns=patterns,
                max_file_size_bytes=config.max_file_size_bytes,
                advanced_config=config.advanced_detection,
            )
            if skip_reason:
                stats["files_skipped"] = 1
                if is_verbose:
                    console.print(f"[dim]Skipped file ({skip_reason}): {target.name}[/dim]")
            else:
                stats["files_scanned"] = 1
        else:
            if output_format.lower() in ("json", "sarif"):
                findings = scan_directory(
                    directory=target,
                    patterns=patterns,
                    respect_gitignore=True,
                    exclude_patterns=config.exclude,
                    max_file_size_bytes=config.max_file_size_bytes,
                    verbose_log=verbose_log,
                    stats=stats,
                    advanced_config=config.advanced_detection,
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
                        advanced_config=config.advanced_detection,
                    )

        if is_verbose and verbose_log:
            max_entries = 50
            if len(verbose_log) > max_entries:
                for log_entry in verbose_log[:max_entries]:
                    console.print(f"[dim]{log_entry}[/dim]")
                remaining = len(verbose_log) - max_entries
                console.print(f"[dim]... and {remaining} more skipped items[/dim]")
            else:
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

        for f in new_findings:
            f.repository = target_dir.name
            f.blocked_by = f.determine_blocking(
                local_block_on=config.local_block_on or config.block_on,
                org_block_on=config.org_config.block_on if config.org_config else None,
            )

        fmt = output_format.lower()
        if fmt == "sarif":
            render_sarif(new_findings, output_path=output_file, patterns=patterns)
        elif fmt == "json":
            render_scan_json(
                findings=new_findings,
                command="scan",
                suppressed_count=len(suppressed_findings),
                output_path=output_file,
            )
        else:
            if suppressed_findings:
                console.print(f"[dim]Suppressed {len(suppressed_findings)} finding(s) matching baseline.[/dim]\n")
            if output_file is not None:
                render_ci_summary(
                    new_findings,
                    files_scanned=stats.get("files_scanned", 0),
                    baseline_suppressed=len(suppressed_findings),
                    block_on=config.block_on,
                    mode_description=f"Scan: {target.name}",
                    output_path=output_file,
                )
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


@main.command(name="ci")
@click.option(
    "--base",
    default=None,
    help="Base Git reference to compare against (e.g. main, origin/main).",
)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "sarif"], case_sensitive=False),
    default="text",
    help="Output format: text (default), json, or sarif.",
)
@click.option(
    "-o",
    "--output",
    "output_file",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to write the report file (text, json, or sarif).",
)
@click.option(
    "--all",
    "scan_all",
    is_flag=True,
    help="Scan the entire repository instead of only changed files.",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    help="Enable verbose diagnostic logging.",
)
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to baseline file (.envguard-baseline.json).",
)
@click.pass_context
def ci_cmd(
    ctx: click.Context,
    base: Optional[str],
    output_format: str,
    output_file: Optional[Path],
    scan_all: bool,
    verbose: bool,
    baseline_path: Optional[Path],
) -> None:
    """Automated security gate optimized for CI/CD pipelines (GitHub Actions, GitLab, etc.)."""
    is_verbose = verbose or ctx.obj.get("VERBOSE", False)
    cwd = Path.cwd()

    try:
        ci_env = detect_ci_environment()
        repo_root = get_git_root_util(cwd) or cwd
        config_file = find_config_file(cwd) or find_config_file(repo_root)
        config = load_config(root_dir=repo_root, config_path=config_file)

        if is_verbose and config.warnings:
            for w in config.warnings:
                err_console.print(f"[yellow]Config warning:[/yellow] {w}")

        patterns = load_default_patterns(
            disabled_rules=config.disabled_rules,
            severity_overrides=config.severity_overrides,
        )

        verbose_log = [] if is_verbose else None
        stats = {"files_scanned": 0, "files_skipped": 0}

        # Determine scan scope: changed files vs full repository
        should_scan_all = scan_all or not config.ci.changed_files_only
        mode_desc = "Full Repository" if should_scan_all else "Changed Files"
        target_base = None

        if should_scan_all:
            findings = scan_directory(
                directory=repo_root,
                patterns=patterns,
                respect_gitignore=True,
                exclude_patterns=config.exclude,
                max_file_size_bytes=config.max_file_size_bytes,
                verbose_log=verbose_log,
                stats=stats,
                advanced_config=config.advanced_detection,
            )
            files_scanned = stats.get("files_scanned", 0)
        else:
            if not is_git_repository(cwd):
                err_msg = "Cannot scan changed files: current directory is not a Git repository."
                if output_format.lower() == "json":
                    render_scan_json([], command="ci", status="error", output_path=output_file)
                raise GitError(err_msg)

            # Determine base reference
            target_base = base or config.ci.base_branch or ci_env.base_ref
            if target_base and target_base.startswith("-"):
                from envguard.exceptions import GitError
                raise GitError(f"Invalid Git reference '{target_base}': reference cannot begin with '-'")
            if not target_base:
                target_base = get_default_base_branch(repo_root)
            if not target_base:
                target_base = "HEAD~1"

            try:
                changed_files = get_changed_files(base=target_base, head="HEAD", repo_path=repo_root)
            except GitError as ge:
                if is_verbose:
                    err_console.print(f"[yellow]Warning:[/yellow] Could not compare against '{target_base}': {ge}. Falling back to full scan.")
                changed_files = None
                mode_desc = "Full Repository (Fallback)"

            if changed_files is not None:
                findings = scan_files(
                    files=changed_files,
                    base_dir=repo_root,
                    patterns=patterns,
                    respect_gitignore=True,
                    exclude_patterns=config.exclude,
                    max_file_size_bytes=config.max_file_size_bytes,
                    verbose_log=verbose_log,
                    stats=stats,
                    advanced_config=config.advanced_detection,
                )
                files_scanned = stats.get("files_scanned", len(changed_files))
            else:
                findings = scan_directory(
                    directory=repo_root,
                    patterns=patterns,
                    respect_gitignore=True,
                    exclude_patterns=config.exclude,
                    max_file_size_bytes=config.max_file_size_bytes,
                    verbose_log=verbose_log,
                    stats=stats,
                    advanced_config=config.advanced_detection,
                )
                files_scanned = stats.get("files_scanned", 0)

        # Baseline filtering
        resolved_baseline = baseline_path or (repo_root / DEFAULT_BASELINE_FILENAME)
        baseline_fingerprints = load_baseline(resolved_baseline) if resolved_baseline.is_file() else set()
        new_findings, suppressed_findings = filter_baseline_findings(findings, baseline_fingerprints)
        suppressed_count = len(suppressed_findings)

        # Determine blocking status
        for f in new_findings:
            f.repository = repo_root.name
            f.blocked_by = f.determine_blocking(
                local_block_on=config.local_block_on or config.block_on,
                org_block_on=config.org_config.block_on if config.org_config else None,
            )
        blocking = [f for f in new_findings if f.blocked_by is not None]
        is_blocked = len(blocking) > 0
        status_str = "failed" if is_blocked else "passed"

        # Emit report based on format
        fmt = output_format.lower()
        if fmt == "sarif":
            render_sarif(new_findings, output_path=output_file, patterns=patterns)
        elif fmt == "json":
            render_scan_json(
                findings=new_findings,
                command="ci",
                status=status_str,
                suppressed_count=suppressed_count,
                output_path=output_file,
            )
        else:
            render_ci_summary(
                findings=new_findings,
                files_scanned=files_scanned,
                baseline_suppressed=suppressed_count,
                block_on=config.block_on,
                ci_env=ci_env,
                mode_description=mode_desc,
                base_reference=target_base if "Changed" in mode_desc else None,
                output_path=output_file,
            )

        # GitHub Actions workflow annotations and job summary
        if ci_env.provider == "github":
            if config.ci.annotations:
                write_github_annotations(new_findings)
            if config.ci.job_summary:
                write_github_job_summary(
                    findings=new_findings,
                    files_scanned=files_scanned,
                    baseline_suppressed=suppressed_count,
                    block_on=config.block_on,
                    ci_env=ci_env,
                )

        if is_blocked:
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
            render_check_json(error=err_msg)
        else:
            handle_cli_error(GitError(err_msg), verbose=is_verbose)
        sys.exit(2)

    try:
        repo_root = get_repo_root(cwd) or cwd
        config_file = find_config_file(cwd) or find_config_file(repo_root)
        config = load_config(root_dir=cwd, config_path=config_file)

        if is_verbose and config.warnings:
            for w in config.warnings:
                err_console.print(f"[yellow]Config warning:[/yellow] {w}")

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
            advanced_config=config.advanced_detection,
        )

        # Baseline resolution
        resolved_baseline = baseline_path
        if not resolved_baseline:
            candidate = repo_root / DEFAULT_BASELINE_FILENAME
            if candidate.is_file():
                resolved_baseline = candidate

        baseline_fingerprints = load_baseline(resolved_baseline) if resolved_baseline else set()
        new_findings, suppressed_findings = filter_baseline_findings(findings, baseline_fingerprints)

        blocking_findings = []
        low_findings = []
        for f in new_findings:
            f.repository = repo_root.name
            f.blocked_by = f.determine_blocking(
                local_block_on=config.local_block_on or config.block_on,
                org_block_on=config.org_config.block_on if config.org_config else None,
            )
            if f.blocked_by is not None:
                blocking_findings.append(f)
            else:
                low_findings.append(f)

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
        config_file = find_config_file(cwd) or find_config_file(repo_root)
        config = load_config(root_dir=cwd, config_path=config_file)

        if config.warnings:
            if output_format.lower() != "json" or is_verbose:
                for w in config.warnings:
                    err_console.print(f"[yellow]Config warning:[/yellow] {w}")

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
            advanced_config=config.advanced_detection,
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
        exists, b_count, b_error = inspect_baseline(baseline_file)
        if exists:
            if b_error is None:
                baseline_status = f"[green]ACTIVE ({b_count} entries)[/green]"
            else:
                baseline_status = "[yellow]INVALID[/yellow]"

        if config_file and config_file.is_file():
            if config.warnings:
                config_status = f"[yellow]WARNING ({config_file.name})[/yellow]"
            else:
                config_status = f"[green]VALID ({config_file.name})[/green]"
        else:
            config_status = "[dim]DEFAULT[/dim]"

        # 5b. Organization Policy status
        org_file = config.org_config_path or find_org_config_file(cwd) or find_org_config_file(repo_root)
        org_status = None
        org_policy_data = None
        if org_file and org_file.is_file():
            if config.org_config and not config.org_config.warnings:
                org_status = f"[green]ACTIVE ({org_file.name})[/green]"
            else:
                org_status = f"[yellow]WARNING ({org_file.name})[/yellow]"
            org_policy_data = {
                "present": True,
                "file": org_file.name,
                "path": str(org_file).replace("\\", "/"),
                "status": "ACTIVE" if (config.org_config and not config.org_config.warnings) else "WARNING",
                "block_on": sorted(list(config.org_config.block_on)) if config.org_config else [],
                "disabled_rules": sorted(list(config.org_config.disabled_rules)) if config.org_config else [],
            }
        else:
            org_status = "[dim]NONE[/dim]"
            org_policy_data = {
                "present": False,
                "status": "NONE",
            }

        has_config_warnings = bool(config.warnings)
        if output_format.lower() == "json":
            # Compute status
            high = sum(1 for f in findings if f.severity == "HIGH")
            med = sum(1 for f in findings if f.severity == "MEDIUM")
            has_drift = diff_result is not None and diff_result.has_drift
            if env_tracked or high > 0:
                overall_status = "CRITICAL"
            elif med > 0 or has_drift or not hook_installed:
                overall_status = "ATTENTION REQUIRED"
            elif len(findings) > 0 or has_config_warnings:
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
                config_warnings=config.warnings,
                org_policy=org_policy_data,
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
                config_warnings=config.warnings,
                org_status=org_status,
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
        disabled_rules = set()
        severity_overrides = {}
        try:
            config = load_config()
            disabled_rules = config.disabled_rules
            severity_overrides = config.severity_overrides
        except Exception:
            # Broken or missing repository configuration should not prevent listing built-in rules
            pass

        patterns = load_default_patterns(
            disabled_rules=disabled_rules,
            severity_overrides=severity_overrides,
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
