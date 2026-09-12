"""Configuration loading and validation for EnvGuard (.envguard.yml)."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set
import yaml

from envguard.exceptions import ConfigurationError
from envguard.utils import add_custom_placeholders

VALID_SEVERITIES = {"HIGH", "MEDIUM", "LOW"}
DEFAULT_BLOCK_ON = ["HIGH", "MEDIUM"]
DEFAULT_MAX_FILE_SIZE_MB = 5.0
SUPPORTED_VERSIONS = {1}


@dataclass
class EnvGuardConfig:
    version: int = 1
    max_file_size_mb: float = DEFAULT_MAX_FILE_SIZE_MB
    exclude: List[str] = field(default_factory=list)
    disabled_rules: Set[str] = field(default_factory=set)
    severity_overrides: Dict[str, str] = field(default_factory=dict)
    placeholders: Set[str] = field(default_factory=set)
    block_on: List[str] = field(default_factory=lambda: list(DEFAULT_BLOCK_ON))
    warnings: List[str] = field(default_factory=list)
    config_file_path: Optional[Path] = None

    @property
    def max_file_size_bytes(self) -> int:
        return int(self.max_file_size_mb * 1024 * 1024)


def find_config_file(root_dir: Path) -> Optional[Path]:
    """Look for .envguard.yml or .envguard.yaml in root directory."""
    for candidate_name in (".envguard.yml", ".envguard.yaml"):
        candidate = root_dir / candidate_name
        if candidate.is_file():
            return candidate
    return None


def load_config(root_dir: Optional[Path] = None, config_path: Optional[Path] = None) -> EnvGuardConfig:
    """Load and validate repository configuration from .envguard.yml or return defaults."""
    target_root = root_dir or Path.cwd()
    file_to_load = config_path or find_config_file(target_root)

    if not file_to_load or not file_to_load.is_file():
        # Return default zero-configuration
        return EnvGuardConfig()

    try:
        content = file_to_load.read_text(encoding="utf-8")
        raw_data = yaml.safe_load(content) or {}
    except yaml.YAMLError as e:
        raise ConfigurationError(f"Invalid YAML in configuration file '{file_to_load.name}': {e}")
    except Exception as e:
        raise ConfigurationError(f"Failed to read configuration file '{file_to_load.name}': {e}")

    if not isinstance(raw_data, dict):
        raise ConfigurationError(f"Configuration file '{file_to_load.name}' must contain a YAML mapping.")

    # 1. Version validation
    version = raw_data.get("version", 1)
    if not isinstance(version, int) or version not in SUPPORTED_VERSIONS:
        supported_str = ", ".join(str(v) for v in sorted(SUPPORTED_VERSIONS))
        raise ConfigurationError(
            f"Unsupported configuration version: {version} in '{file_to_load.name}' (supported: {supported_str})"
        )

    # 2. Scan options
    scan_section = raw_data.get("scan", {})
    max_mb = scan_section.get("max_file_size_mb", DEFAULT_MAX_FILE_SIZE_MB)
    try:
        max_mb = float(max_mb)
        if max_mb <= 0:
            raise ValueError
    except (ValueError, TypeError):
        raise ConfigurationError("scan.max_file_size_mb must be a positive number")

    # 3. Excludes
    exclude_list = raw_data.get("exclude", [])
    if not isinstance(exclude_list, list):
        raise ConfigurationError("'exclude' must be a list of glob patterns")
    exclude = [str(x) for x in exclude_list]

    # 4. Rules & Severity Overrides
    rules_section = raw_data.get("rules", {})
    if not isinstance(rules_section, dict):
        raise ConfigurationError("'rules' must be a dictionary")

    disabled_list = rules_section.get("disable", [])
    if not isinstance(disabled_list, list):
        raise ConfigurationError("'rules.disable' must be a list of rule IDs")
    disabled_rules = {str(r) for r in disabled_list}

    raw_overrides = rules_section.get("severity_overrides", {})
    if not isinstance(raw_overrides, dict):
        raise ConfigurationError("'rules.severity_overrides' must be a dictionary")

    severity_overrides: Dict[str, str] = {}
    for rule_id, sev_val in raw_overrides.items():
        sev_upper = str(sev_val).upper()
        if sev_upper not in VALID_SEVERITIES:
            raise ConfigurationError(
                f"Invalid severity override '{sev_val}' for rule '{rule_id}'. Allowed: {', '.join(sorted(VALID_SEVERITIES))}"
            )
        severity_overrides[str(rule_id)] = sev_upper

    # 5. Placeholders
    placeholder_list = raw_data.get("placeholders", [])
    if not isinstance(placeholder_list, list):
        raise ConfigurationError("'placeholders' must be a list of strings")
    placeholders = {str(p).strip().lower() for p in placeholder_list if str(p).strip()}

    # Merge custom placeholders into global utils whitelist
    if placeholders:
        add_custom_placeholders(placeholders)

    # 6. Git block_on
    git_section = raw_data.get("git", {})
    block_on_list = git_section.get("block_on", DEFAULT_BLOCK_ON)
    if not isinstance(block_on_list, list):
        raise ConfigurationError("'git.block_on' must be a list of severities")
    block_on = [str(b).upper() for b in block_on_list]

    # 7. Check for unknown rule IDs to produce warnings
    warnings: List[str] = []
    # Known rule IDs
    from envguard.patterns import load_default_patterns
    known_rules = {p.id for p in load_default_patterns()}

    for d_rule in disabled_rules:
        if d_rule not in known_rules:
            warnings.append(f"Unknown rule ID '{d_rule}' in rules.disable")
    for o_rule in severity_overrides:
        if o_rule not in known_rules:
            warnings.append(f"Unknown rule ID '{o_rule}' in rules.severity_overrides")

    return EnvGuardConfig(
        version=version,
        max_file_size_mb=max_mb,
        exclude=exclude,
        disabled_rules=disabled_rules,
        severity_overrides=severity_overrides,
        placeholders=placeholders,
        block_on=block_on,
        warnings=warnings,
        config_file_path=file_to_load,
    )
