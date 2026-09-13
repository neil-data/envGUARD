"""Configuration loading and validation for EnvGuard (.envguard.yml)."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set
import yaml

from envguard.detectors.scoring import AdvancedDetectionConfig
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
    advanced_detection: AdvancedDetectionConfig = field(default_factory=AdvancedDetectionConfig)
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

    config_filename = file_to_load.name

    try:
        content = file_to_load.read_text(encoding="utf-8")
        raw_data = yaml.safe_load(content)
        if raw_data is None:
            raw_data = {}
    except yaml.YAMLError as e:
        raise ConfigurationError(
            f"Invalid YAML in configuration file '{config_filename}': {e}",
            config_path=config_filename,
        )
    except Exception as e:
        raise ConfigurationError(
            f"Failed to read configuration file '{config_filename}': {e}",
            config_path=config_filename,
        )

    if not isinstance(raw_data, dict):
        raise ConfigurationError(
            f"Configuration file '{config_filename}' must contain a YAML mapping.",
            config_path=config_filename,
            expected="mapping / dictionary",
            received=type(raw_data).__name__,
        )

    # 1. Version validation
    version = raw_data.get("version")
    if version is None:
        version = 1
    if not isinstance(version, int) or version not in SUPPORTED_VERSIONS:
        supported_str = ", ".join(str(v) for v in sorted(SUPPORTED_VERSIONS))
        raise ConfigurationError(
            f"Unsupported configuration version: {version} in '{config_filename}' (supported: {supported_str})",
            field="version",
            expected=supported_str,
            received=str(version),
            config_path=config_filename,
        )

    # 2. Scan options
    scan_section = raw_data.get("scan")
    if scan_section is None:
        scan_section = {}
    elif not isinstance(scan_section, dict):
        raise ConfigurationError(
            "'scan' must be a dictionary",
            field="scan",
            expected="dictionary",
            received=type(scan_section).__name__,
            config_path=config_filename,
        )

    max_mb = scan_section.get("max_file_size_mb")
    if max_mb is None:
        max_mb = DEFAULT_MAX_FILE_SIZE_MB
    try:
        max_mb = float(max_mb)
        if max_mb <= 0:
            raise ValueError
    except (ValueError, TypeError):
        raise ConfigurationError(
            "scan.max_file_size_mb must be a positive number",
            field="scan.max_file_size_mb",
            expected="positive number",
            received=str(max_mb),
            config_path=config_filename,
        )

    # 3. Excludes
    exclude_val = raw_data.get("exclude")
    if exclude_val is None:
        exclude_val = []
    if not isinstance(exclude_val, list):
        raise ConfigurationError(
            "'exclude' must be a list of glob patterns",
            field="exclude",
            expected="list",
            received=type(exclude_val).__name__,
            config_path=config_filename,
        )
    exclude = [str(x) for x in exclude_val]

    # 4. Rules & Severity Overrides
    rules_section = raw_data.get("rules")
    if rules_section is None:
        rules_section = {}
    elif not isinstance(rules_section, dict):
        raise ConfigurationError(
            "'rules' must be a dictionary",
            field="rules",
            expected="dictionary",
            received=type(rules_section).__name__,
            config_path=config_filename,
        )

    # Support both 'disabled' (canonical) and 'disable' (backward compatibility)
    disabled_val = rules_section.get("disabled")
    if disabled_val is None:
        disabled_val = rules_section.get("disable")
    if disabled_val is None:
        disabled_val = []
    if not isinstance(disabled_val, list):
        raise ConfigurationError(
            "rules.disabled must be a list of rule IDs",
            field="rules.disabled",
            expected="list",
            received=type(disabled_val).__name__,
            config_path=config_filename,
            example="rules:\n  disabled:\n    - generic-credential",
        )
    disabled_rules = {str(r) for r in disabled_val}

    raw_overrides = rules_section.get("severity_overrides")
    if raw_overrides is None:
        raw_overrides = {}
    if not isinstance(raw_overrides, dict):
        raise ConfigurationError(
            "rules.severity_overrides must be a dictionary",
            field="rules.severity_overrides",
            expected="dictionary",
            received=type(raw_overrides).__name__,
            config_path=config_filename,
            example="rules:\n  severity_overrides:\n    generic-secret: LOW",
        )

    severity_overrides: Dict[str, str] = {}
    for rule_id, sev_val in raw_overrides.items():
        if not isinstance(sev_val, (str, int)):
            raise ConfigurationError(
                f"Invalid severity override '{sev_val}' for rule '{rule_id}'. Allowed: {', '.join(sorted(VALID_SEVERITIES))}",
                field=f"rules.severity_overrides.{rule_id}",
                expected=f"one of {', '.join(sorted(VALID_SEVERITIES))}",
                received=type(sev_val).__name__,
                config_path=config_filename,
            )
        sev_upper = str(sev_val).upper()
        if sev_upper not in VALID_SEVERITIES:
            raise ConfigurationError(
                f"Invalid severity override '{sev_val}' for rule '{rule_id}'. Allowed: {', '.join(sorted(VALID_SEVERITIES))}",
                field=f"rules.severity_overrides.{rule_id}",
                expected=f"one of {', '.join(sorted(VALID_SEVERITIES))}",
                received=sev_upper,
                config_path=config_filename,
            )
        severity_overrides[str(rule_id)] = sev_upper

    # 5. Placeholders
    placeholder_val = raw_data.get("placeholders")
    if placeholder_val is None:
        placeholder_val = []
    if not isinstance(placeholder_val, list):
        raise ConfigurationError(
            "'placeholders' must be a list of strings",
            field="placeholders",
            expected="list",
            received=type(placeholder_val).__name__,
            config_path=config_filename,
        )
    placeholders = {str(p).strip().lower() for p in placeholder_val if str(p).strip()}

    # Merge custom placeholders into global utils whitelist
    if placeholders:
        add_custom_placeholders(placeholders)

    # 6. Block on (check scan.block_on or git.block_on)
    git_section = raw_data.get("git")
    if git_section is None:
        git_section = {}
    elif not isinstance(git_section, dict):
        raise ConfigurationError(
            "'git' must be a dictionary",
            field="git",
            expected="dictionary",
            received=type(git_section).__name__,
            config_path=config_filename,
        )

    block_on_val = scan_section.get("block_on")
    if block_on_val is None:
        block_on_val = git_section.get("block_on")
    if block_on_val is None:
        block_on_val = DEFAULT_BLOCK_ON

    if not isinstance(block_on_val, list):
        raise ConfigurationError(
            "'block_on' must be a list of severities",
            field="block_on",
            expected="list",
            received=type(block_on_val).__name__,
            config_path=config_filename,
        )
    block_on = [str(b).upper() for b in block_on_val]

    # 7. Reporting section
    reporting_section = raw_data.get("reporting")
    if reporting_section is None:
        reporting_section = {}
    elif not isinstance(reporting_section, dict):
        raise ConfigurationError(
            "'reporting' must be a dictionary",
            field="reporting",
            expected="dictionary",
            received=type(reporting_section).__name__,
            config_path=config_filename,
        )

    # 8. Advanced Detection section
    warnings: List[str] = []
    adv_section = raw_data.get("advanced_detection")
    if adv_section is None:
        adv_config = AdvancedDetectionConfig()
    elif not isinstance(adv_section, dict):
        raise ConfigurationError(
            "'advanced_detection' must be a dictionary",
            field="advanced_detection",
            expected="dictionary",
            received=type(adv_section).__name__,
            config_path=config_filename,
        )
    else:
        entropy_sec = adv_section.get("entropy")
        entropy_enabled = True
        entropy_min_len = 20
        entropy_thresh = 4.0

        if entropy_sec is not None:
            if not isinstance(entropy_sec, dict):
                raise ConfigurationError(
                    "'advanced_detection.entropy' must be a dictionary",
                    field="advanced_detection.entropy",
                    expected="dictionary",
                    received=type(entropy_sec).__name__,
                    config_path=config_filename,
                )
            if "enabled" in entropy_sec:
                en = entropy_sec["enabled"]
                if not isinstance(en, bool):
                    raise ConfigurationError(
                        "'advanced_detection.entropy.enabled' must be a boolean",
                        field="advanced_detection.entropy.enabled",
                        expected="boolean",
                        received=type(en).__name__,
                        config_path=config_filename,
                    )
                entropy_enabled = en

            if "min_length" in entropy_sec:
                ml = entropy_sec["min_length"]
                if not isinstance(ml, int) or isinstance(ml, bool) or ml <= 0:
                    raise ConfigurationError(
                        "'advanced_detection.entropy.min_length' must be a positive integer",
                        field="advanced_detection.entropy.min_length",
                        expected="positive integer",
                        received=str(ml),
                        config_path=config_filename,
                    )
                entropy_min_len = ml

            if "threshold" in entropy_sec:
                th = entropy_sec["threshold"]
                if isinstance(th, bool) or not isinstance(th, (int, float)) or not (1.0 <= th <= 8.0):
                    raise ConfigurationError(
                        "'advanced_detection.entropy.threshold' must be a number between 1.0 and 8.0",
                        field="advanced_detection.entropy.threshold",
                        expected="float between 1.0 and 8.0",
                        received=str(th),
                        config_path=config_filename,
                    )
                entropy_thresh = float(th)

        jwt_sec = adv_section.get("jwt")
        jwt_enabled = True
        if jwt_sec is not None:
            if not isinstance(jwt_sec, dict):
                raise ConfigurationError(
                    "'advanced_detection.jwt' must be a dictionary",
                    field="advanced_detection.jwt",
                    expected="dictionary",
                    received=type(jwt_sec).__name__,
                    config_path=config_filename,
                )
            if "enabled" in jwt_sec:
                jen = jwt_sec["enabled"]
                if not isinstance(jen, bool):
                    raise ConfigurationError(
                        "'advanced_detection.jwt.enabled' must be a boolean",
                        field="advanced_detection.jwt.enabled",
                        expected="boolean",
                        received=type(jen).__name__,
                        config_path=config_filename,
                    )
                jwt_enabled = jen

        context_sec = adv_section.get("context_analysis")
        context_enabled = True
        if context_sec is not None:
            if not isinstance(context_sec, dict):
                raise ConfigurationError(
                    "'advanced_detection.context_analysis' must be a dictionary",
                    field="advanced_detection.context_analysis",
                    expected="dictionary",
                    received=type(context_sec).__name__,
                    config_path=config_filename,
                )
            if "enabled" in context_sec:
                cen = context_sec["enabled"]
                if not isinstance(cen, bool):
                    raise ConfigurationError(
                        "'advanced_detection.context_analysis.enabled' must be a boolean",
                        field="advanced_detection.context_analysis.enabled",
                        expected="boolean",
                        received=type(cen).__name__,
                        config_path=config_filename,
                    )
                context_enabled = cen

        known_adv_keys = {"entropy", "jwt", "context_analysis"}
        for k in adv_section:
            if k not in known_adv_keys:
                warnings.append(f"Unknown key '{k}' in advanced_detection")

        adv_config = AdvancedDetectionConfig(
            entropy_enabled=entropy_enabled,
            entropy_min_length=entropy_min_len,
            entropy_threshold=entropy_thresh,
            jwt_enabled=jwt_enabled,
            context_enabled=context_enabled,
        )

    # 9. Check for unknown rule IDs to produce warnings
    from envguard.patterns import load_default_patterns
    known_rules = {p.id for p in load_default_patterns()}

    for d_rule in disabled_rules:
        if d_rule not in known_rules:
            warnings.append(f"Unknown rule ID '{d_rule}' in rules.disabled")
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
        advanced_detection=adv_config,
        warnings=warnings,
        config_file_path=file_to_load,
    )
