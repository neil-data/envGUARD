"""EnvGuard doctor diagnostics checks.

Checks:
- Python version
- EnvGuard version
- Git command availability
- Git repository detection
- Repository configuration (.envguard.yml)
- Rule definitions loading
- Ignore configuration (.envguardignore & .gitignore)
- Pre-commit hook installation
- Baseline file (validity if present)
"""

from dataclasses import dataclass, field
from pathlib import Path
import shutil
import sys
from typing import Dict, List, Optional

from envguard import __version__
from envguard.baseline import load_baseline
from envguard.config import load_config
from envguard.git_handler import get_repo_root, is_git_repo
from envguard.hook import is_hook_installed
from envguard.patterns import load_default_patterns


@dataclass
class DiagnosticCheck:
    name: str
    status: str  # "PASS", "WARNING", "ERROR"
    details: str
    recommendation: Optional[str] = None


@dataclass
class DiagnosticReport:
    checks: List[DiagnosticCheck] = field(default_factory=list)
    overall_status: str = "PASS"  # "PASS", "WARNING", "ERROR"

    @property
    def passed_count(self) -> int:
        return sum(1 for c in self.checks if c.status == "PASS")

    @property
    def warning_count(self) -> int:
        return sum(1 for c in self.checks if c.status == "WARNING")

    @property
    def error_count(self) -> int:
        return sum(1 for c in self.checks if c.status == "ERROR")


def run_diagnostics(repo_path: Path) -> DiagnosticReport:
    """Run all doctor diagnostic checks for the repository."""
    report = DiagnosticReport()

    # 1. Python
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 9):
        report.checks.append(DiagnosticCheck("Python Runtime", "PASS", f"Python {py_ver} (Compatible >= 3.9)"))
    else:
        report.checks.append(DiagnosticCheck("Python Runtime", "WARNING", f"Python {py_ver} (might be incompatible with some features)", "Upgrade to Python 3.9 or newer."))

    # 2. EnvGuard Version
    report.checks.append(DiagnosticCheck("EnvGuard Version", "PASS", f"v{__version__}"))

    # 3. Git CI
    git_bin = shutil.which("git")
    if git_bin:
        report.checks.append(DiagnosticCheck("Git Command", "PASS", f"Available at {git_bin}"))
    else:
        report.checks.append(DiagnosticCheck("Git Command", "ERROR", "Git executable not found in PATH", "Install Git and ensure it is added to PATH."))

    # 4. Git Repository (centralized detection via git_handler)
    is_git = is_git_repo(repo_path)
    root = get_repo_root(repo_path) or repo_path
    if is_git:
        resolved_root = root.resolve()
        resolved_repo = repo_path.resolve()
        user_home = Path.home().resolve()

        if resolved_root == user_home:
            report.checks.append(
                DiagnosticCheck(
                    "Git Repository",
                    "WARNING",
                    f"Git root is user home directory ({root})",
                    "Your user home directory is a Git repository. Initialize Git inside the project directory or remove the home .git repository.",
                )
            )
        else:
            try:
                rel_parts = resolved_repo.relative_to(resolved_root).parts
                is_far_above = len(rel_parts) >= 2
            except ValueError:
                is_far_above = False

            if is_far_above:
                report.checks.append(
                    DiagnosticCheck(
                        "Git Repository",
                        "WARNING",
                        f"Git root is far above current directory ({root})",
                        "Current directory is nested within a parent Git repository. Consider initializing Git in the project root.",
                    )
                )
            else:
                report.checks.append(DiagnosticCheck("Git Repository", "PASS", f"Initialized at {root}"))
    else:
        report.checks.append(DiagnosticCheck("Git Repository", "WARNING", "Not a Git repository", "Run 'git init' to enable Git-specific protection."))

    # 5. Configuration
    config_file = repo_path / ".envguard.yml"
    if config_file.is_file():
        try:
            cfg = load_config(repo_path)
            report.checks.append(DiagnosticCheck("Repository Config", "PASS", ".envguard.yml present and valid"))
        except Exception as e:
            report.checks.append(DiagnosticCheck("Repository Config", "ERROR", f".envguard.yml parse error: {e}", "Fix SYNTAX errors in .envguard.yml."))
    else:
        report.checks.append(DiagnosticCheck("Repository Config", "WARNING", "No .envguard.yml (using defaults)", "Run 'envguard init' to generate a configuration file."))

    # 6. Rules
    try:
        patterns = load_default_patterns()
        enabled = sum(1 for p in patterns if p.enabled)
        report.checks.append(DiagnosticCheck("Secret Rules", "PASS", f"{enabled} rules active ({len(patterns)} total)"))
    except Exception as e:
        report.checks.append(DiagnosticCheck("Secret Rules", "ERROR", f"Error loading rules: {e}", "Reinstall EnvGuard."))

    # 7. Ignore Configuration
    has_gitignore = (repo_path / ".gitignore").is_file()
    has_envignore = (repo_path / ".envguardignore").is_file()
    if has_envignore and has_gitignore:
        report.checks.append(DiagnosticCheck("Ignore Setup", "PASS", "Both .gitignore and .envguardignore present"))
    elif has_gitignore:
        report.checks.append(DiagnosticCheck("Ignore Setup", "PASS", ".gitignore present (no .envguardignore)"))
    elif has_envignore:
        report.checks.append(DiagnosticCheck("Ignore Setup", "PASS", ".envguardignore present (no .gitignore)"))
    else:
        report.checks.append(DiagnosticCheck("Ignore Setup", "PASS", "No ignore files configured"))

    # 8. Pre-commit hook
    if is_git:
        if is_hook_installed(root):
            report.checks.append(DiagnosticCheck("Pre-Commit Hook", "PASS", "EnvGuard pre-commit hook active"))
        else:
            report.checks.append(DiagnosticCheck("Pre-Commit Hook", "WARNING", "Hook not installed", "Run 'envguard install-hook' to prevent accidental commits."))

    # 9. Baseline
    baseline_f = repo_path / ".envguard-baseline.json"
    if baseline_f.is_file():
        try:
            fingerprints = load_baseline(baseline_f)
            count = len(fingerprints)
            report.checks.append(DiagnosticCheck("Historical Baseline", "PASS", f"present ({count} fingerprints)"))
        except Exception as e:
            report.checks.append(DiagnosticCheck("Historical Baseline", "ERROR", f"Baseline file is corrupt: {e}", "Run 'envguard baseline create' to regenerate."))
    else:
        report.checks.append(DiagnosticCheck("Historical Baseline", "PASS", "No baseline file (standard)"))

    # Determine overall status
    if report.error_count > 0:
        report.overall_status = "ERROR"
    elif report.warning_count > 0:
        report.overall_status = "WARNING"
    else:
        report.overall_status = "PASS"

    return report
