"""Configuration Linter for EnvGuard v0.9.0.

Provides rigorous, unified configuration assurance for .envguard.yml and .envguard-org.yml:
- Field types, allowed values, and severity levels.
- Unknown and typo'd keys in top-level and sub-sections.
- Invalid rule IDs verified against the EnvGuard pattern catalog.
- Conflicting settings (e.g. disabled rules with severity overrides).
- Organization vs. Local security floor policy conflicts.
- Git tracking risks and .gitignore verification for .env.
"""

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import yaml

from envguard.config import (
    VALID_SEVERITIES,
    find_config_file,
    find_org_config_file,
    load_raw_config_file,
)
from envguard.exceptions import ConfigurationError
from envguard.git_handler import is_env_tracked, is_git_repo
from envguard.git_utils import is_git_repository, run_git
from envguard.patterns import load_default_patterns


KNOWN_SCAN_KEYS = {"max_file_size_mb", "block_on", "respect_gitignore"}
KNOWN_RULES_KEYS = {"disabled", "disable", "severity_overrides", "locked_disabled_rules"}
KNOWN_ADVANCED_KEYS = {
    "entropy_threshold",
    "detect_jwt",
    "high_entropy_min_length",
    "confidence_boost_patterns",
}
KNOWN_CI_KEYS = {
    "changed_files_only",
    "base_branch",
    "fail_on_warning",
    "emit_annotations",
    "step_summary",
}
KNOWN_REPORTING_KEYS = {"format", "output"}


@dataclass
class LintDiagnostic:
    file: str
    field: Optional[str]
    level: str  # "ERROR", "WARNING", "PASS"
    message: str
    recommendation: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None


@dataclass
class ConfigLintReport:
    target_root: Path
    local_config_path: Optional[Path] = None
    org_config_path: Optional[Path] = None
    diagnostics: List[LintDiagnostic] = field(default_factory=list)

    @property
    def error_count(self) -> int:
        return sum(1 for d in self.diagnostics if d.level == "ERROR")

    @property
    def warning_count(self) -> int:
        return sum(1 for d in self.diagnostics if d.level == "WARNING")

    @property
    def pass_count(self) -> int:
        return sum(1 for d in self.diagnostics if d.level == "PASS")

    @property
    def is_clean(self) -> bool:
        return self.error_count == 0

    @property
    def exit_code(self) -> int:
        return 1 if self.error_count > 0 else 0


def get_known_rule_ids() -> Set[str]:
    """Retrieve all valid rule IDs from the default pattern catalog."""
    patterns = load_default_patterns()
    return {p.id for p in patterns}


def _check_subsection_keys(
    data: Dict[str, Any],
    section_name: str,
    known_keys: Set[str],
    filename: str,
    diagnostics: List[LintDiagnostic],
) -> None:
    """Check for unknown or typo'd keys within a configuration sub-dictionary."""
    sub_dict = data.get(section_name)
    if isinstance(sub_dict, dict):
        for k in sub_dict:
            if k not in known_keys:
                diagnostics.append(
                    LintDiagnostic(
                        file=filename,
                        field=f"{section_name}.{k}",
                        level="WARNING",
                        message=f"Unknown key '{k}' in '{section_name}' section.",
                        recommendation=f"Allowed keys in '{section_name}': {', '.join(sorted(known_keys))}",
                    )
                )


def lint_single_file(
    file_path: Path,
    known_rule_ids: Set[str],
    is_org_policy: bool = False,
) -> Tuple[Optional[Any], List[LintDiagnostic]]:
    """Thoroughly lint a single configuration or org-policy YAML file."""
    diagnostics: List[LintDiagnostic] = []
    fname = file_path.name

    # 1. File existence and basic YAML parsing
    if not file_path.is_file():
        diagnostics.append(
            LintDiagnostic(
                file=fname,
                field=None,
                level="WARNING",
                message=f"Configuration file '{fname}' not found.",
                recommendation="Run 'envguard init' to create a starter configuration file.",
            )
        )
        return None, diagnostics

    try:
        raw_text = file_path.read_text(encoding="utf-8-sig", errors="replace")
        raw_yaml = yaml.safe_load(raw_text)
    except yaml.YAMLError as ye:
        line = getattr(getattr(ye, "problem_mark", None), "line", None)
        col = getattr(getattr(ye, "problem_mark", None), "column", None)
        diagnostics.append(
            LintDiagnostic(
                file=fname,
                field=None,
                level="ERROR",
                message=f"YAML syntax error: {ye}",
                recommendation="Ensure the YAML file has valid syntax and indentation.",
                line=line + 1 if line is not None else None,
                column=col + 1 if col is not None else None,
            )
        )
        return None, diagnostics

    if raw_yaml is None:
        diagnostics.append(
            LintDiagnostic(
                file=fname,
                field=None,
                level="WARNING",
                message="Configuration file is empty.",
                recommendation="Add valid EnvGuard configuration directives.",
            )
        )
        return None, diagnostics

    if not isinstance(raw_yaml, dict):
        diagnostics.append(
            LintDiagnostic(
                file=fname,
                field=None,
                level="ERROR",
                message=f"Root configuration element must be a dictionary, got {type(raw_yaml).__name__}.",
                recommendation="Ensure the top-level YAML structure is key-value mappings.",
            )
        )
        return None, diagnostics

    # 2. Check sub-section typo'd keys
    _check_subsection_keys(raw_yaml, "scan", KNOWN_SCAN_KEYS, fname, diagnostics)
    _check_subsection_keys(raw_yaml, "rules", KNOWN_RULES_KEYS, fname, diagnostics)
    _check_subsection_keys(raw_yaml, "advanced_detection", KNOWN_ADVANCED_KEYS, fname, diagnostics)
    _check_subsection_keys(raw_yaml, "ci", KNOWN_CI_KEYS, fname, diagnostics)
    _check_subsection_keys(raw_yaml, "reporting", KNOWN_REPORTING_KEYS, fname, diagnostics)

    # 3. Use core load_raw_config_file to validate field types, allowed values, severities
    parsed_config = None
    try:
        parsed_config = load_raw_config_file(file_path)
        # Collect top-level unknown key warnings already detected by load_raw_config_file
        for w in parsed_config.warnings:
            # Extract key name if possible
            match = re.search(r"Unknown top-level key '([^']+)'", w)
            key_name = match.group(1) if match else None
            diagnostics.append(
                LintDiagnostic(
                    file=fname,
                    field=key_name,
                    level="WARNING",
                    message=w,
                    recommendation="Review spelling and remove unrecognized top-level keys.",
                )
            )
    except ConfigurationError as ce:
        diagnostics.append(
            LintDiagnostic(
                file=fname,
                field=ce.field,
                level="ERROR",
                message=ce.message,
                recommendation=f"Expected {ce.expected}" if ce.expected else "Fix configuration value.",
            )
        )
        return None, diagnostics

    # 4. Check for invalid rule IDs
    if parsed_config:
        all_rules_in_config = set(parsed_config.disabled_rules) | set(parsed_config.severity_overrides.keys())
        if hasattr(parsed_config, "locked_disabled_rules"):
            all_rules_in_config |= set(parsed_config.locked_disabled_rules)

        for r_id in sorted(all_rules_in_config):
            if r_id not in known_rule_ids:
                diagnostics.append(
                    LintDiagnostic(
                        file=fname,
                        field=f"rules.{r_id}",
                        level="WARNING",
                        message=f"Rule ID '{r_id}' is not recognized in the EnvGuard rule catalog.",
                        recommendation="Run 'envguard rules list' to inspect available rule IDs.",
                    )
                )

        # 5. Check for conflicting settings (rule in both disabled and severity_overrides)
        for r_id in sorted(parsed_config.disabled_rules):
            if r_id in parsed_config.severity_overrides:
                diagnostics.append(
                    LintDiagnostic(
                        file=fname,
                        field=f"rules.{r_id}",
                        level="ERROR",
                        message=f"Rule '{r_id}' cannot be both disabled and have a severity override.",
                        recommendation=f"Remove '{r_id}' from either 'rules.disabled' or 'rules.severity_overrides'.",
                    )
                )

    return parsed_config, diagnostics


def check_env_git_risk(target_root: Path) -> List[LintDiagnostic]:
    """Inspect Git tracking status and .gitignore exclusion for .env."""
    diagnostics: List[LintDiagnostic] = []
    is_git = is_git_repo(target_root) or is_git_repository(target_root)

    if not is_git:
        # Check if local .gitignore exists
        gitignore_path = target_root / ".gitignore"
        env_path = target_root / ".env"
        if env_path.is_file():
            if not gitignore_path.is_file():
                diagnostics.append(
                    LintDiagnostic(
                        file=".gitignore",
                        field="git.ignore",
                        level="WARNING",
                        message="'.env' file exists but repository is not a Git repo and '.gitignore' is missing.",
                        recommendation="Initialize Git ('git init') and exclude '.env' in '.gitignore'.",
                    )
                )
        return diagnostics

    # 1. Check if .env is tracked in git index
    if is_env_tracked(target_root):
        diagnostics.append(
            LintDiagnostic(
                file=".env",
                field="git.tracking",
                level="ERROR",
                message="'.env' is tracked in Git index! Secrets inside may be exposed in Git history.",
                recommendation="Run 'git rm --cached .env' and commit the removal immediately.",
            )
        )

    # 2. Check if .gitignore excludes .env
    proc = run_git(["check-ignore", "-q", ".env"], cwd=target_root)
    if proc.returncode != 0:
        # .env is NOT ignored
        env_file = target_root / ".env"
        level = "WARNING" if not env_file.exists() else "ERROR"
        diagnostics.append(
            LintDiagnostic(
                file=".gitignore",
                field="git.ignore",
                level=level,
                message="'.env' is not excluded by '.gitignore'. Running 'git add .' could stage plaintext secrets.",
                recommendation="Add '.env' to '.gitignore' or run 'envguard fix --apply'.",
            )
        )

    return diagnostics


def lint_configuration(
    target_root: Path,
    config_path: Optional[Path] = None,
    org_path: Optional[Path] = None,
) -> ConfigLintReport:
    """Run full configuration linting across local config, org policy, and Git environment."""
    report = ConfigLintReport(target_root=target_root)
    resolved_root = target_root.resolve()
    known_rules = get_known_rule_ids()

    file_to_load = config_path or find_config_file(resolved_root)
    org_file_to_load = org_path or find_org_config_file(resolved_root)

    report.local_config_path = file_to_load
    report.org_config_path = org_file_to_load

    local_cfg = None
    org_cfg = None

    # 1. Lint local configuration file
    if file_to_load and file_to_load.is_file():
        local_cfg, local_diags = lint_single_file(file_to_load, known_rules, is_org_policy=False)
        report.diagnostics.extend(local_diags)
    else:
        report.diagnostics.append(
            LintDiagnostic(
                file=file_to_load.name if file_to_load else ".envguard.yml",
                field=None,
                level="WARNING",
                message="No local configuration file (.envguard.yml) found. Using built-in defaults.",
                recommendation="Run 'envguard init' to create a starter configuration file.",
            )
        )

    # 2. Lint organization policy file
    if org_file_to_load and org_file_to_load.is_file():
        org_cfg, org_diags = lint_single_file(org_file_to_load, known_rules, is_org_policy=True)
        report.diagnostics.extend(org_diags)

    # 3. Check organization policy vs local policy conflicts
    if local_cfg and org_cfg:
        loc_name = file_to_load.name if file_to_load else ".envguard.yml"
        org_name = org_file_to_load.name if org_file_to_load else ".envguard-org.yml"

        # Check A: Local disabled_rules trying to disable org-enforced rule
        for d_rule in sorted(local_cfg.disabled_rules):
            if d_rule not in org_cfg.disabled_rules:
                report.diagnostics.append(
                    LintDiagnostic(
                        file=loc_name,
                        field="rules.disabled",
                        level="ERROR",
                        message=f"Local configuration disables rule '{d_rule}', which is enforced by organization policy '{org_name}'.",
                        recommendation=f"Remove '{d_rule}' from local 'rules.disabled'.",
                    )
                )

        # Check B: Local block_on trying to weaken org block_on
        if local_cfg.has_explicit_block_on:
            missing = set(org_cfg.block_on) - set(local_cfg.block_on)
            if missing:
                missing_sorted = sorted(missing)
                report.diagnostics.append(
                    LintDiagnostic(
                        file=loc_name,
                        field="scan.block_on",
                        level="ERROR",
                        message=f"Local 'block_on' weakens organization policy: severity {missing_sorted} is required by '{org_name}'.",
                        recommendation=f"Add {missing_sorted} to 'scan.block_on'.",
                    )
                )

        # Check C: Local severity override downgrading org override
        severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        for rule_id, local_sev in sorted(local_cfg.severity_overrides.items()):
            if rule_id in org_cfg.severity_overrides:
                org_sev = org_cfg.severity_overrides[rule_id]
                if severity_rank.get(local_sev, 0) < severity_rank.get(org_sev, 0):
                    report.diagnostics.append(
                        LintDiagnostic(
                            file=loc_name,
                            field=f"rules.severity_overrides.{rule_id}",
                            level="ERROR",
                            message=f"Local severity override for '{rule_id}' ({local_sev}) downgrades organization policy ({org_sev}).",
                            recommendation=f"Raise severity override for '{rule_id}' to at least '{org_sev}'.",
                        )
                    )

    # 4. Check Git tracking and .gitignore risk for .env
    git_diags = check_env_git_risk(resolved_root)
    report.diagnostics.extend(git_diags)

    # 5. If zero errors and zero warnings, add PASS diagnostic
    if not report.diagnostics:
        report.diagnostics.append(
            LintDiagnostic(
                file=file_to_load.name if file_to_load else ".envguard.yml",
                field=None,
                level="PASS",
                message="Configuration and security policies validated with zero issues.",
            )
        )

    return report
