"""Tests for EnvGuard configuration loading and validation (.envguard.yml)."""

from pathlib import Path
import pytest

from envguard.config import EnvGuardConfig, load_config
from envguard.exceptions import ConfigurationError
from envguard.utils import is_placeholder


def test_missing_config_returns_defaults(tmp_path):
    config = load_config(root_dir=tmp_path)
    assert isinstance(config, EnvGuardConfig)
    assert config.version == 1
    assert config.max_file_size_mb == 5.0
    assert config.disabled_rules == set()
    assert config.block_on == ["HIGH", "MEDIUM"]


def test_valid_config_overrides_defaults(tmp_path):
    config_file = tmp_path / ".envguard.yml"
    config_file.write_text(
        """
version: 1

scan:
  max_file_size_mb: 10

exclude:
  - tests/fixtures/**
  - vendor/**

rules:
  disable:
    - generic-secret
  severity_overrides:
    api-key-assignment: HIGH

placeholders:
  - custom_dummy_key_123

git:
  block_on:
    - HIGH
""",
        encoding="utf-8",
    )

    config = load_config(root_dir=tmp_path)
    assert config.version == 1
    assert config.max_file_size_mb == 10.0
    assert "vendor/**" in config.exclude
    assert "generic-secret" in config.disabled_rules
    assert config.severity_overrides.get("api-key-assignment") == "HIGH"
    assert config.block_on == ["HIGH"]
    assert "custom_dummy_key_123" in config.placeholders
    assert is_placeholder("custom_dummy_key_123") is True


def test_invalid_yaml_raises_configuration_error(tmp_path):
    config_file = tmp_path / ".envguard.yml"
    config_file.write_text("version: 1\n  bad_indent:\n- invalid:", encoding="utf-8")

    with pytest.raises(ConfigurationError) as exc_info:
        load_config(root_dir=tmp_path)
    assert "Invalid YAML" in str(exc_info.value)


def test_unsupported_version_raises_configuration_error(tmp_path):
    config_file = tmp_path / ".envguard.yml"
    config_file.write_text("version: 99\n", encoding="utf-8")

    with pytest.raises(ConfigurationError) as exc_info:
        load_config(root_dir=tmp_path)
    assert "Unsupported configuration version: 99" in str(exc_info.value)


def test_invalid_severity_override_raises_configuration_error(tmp_path):
    config_file = tmp_path / ".envguard.yml"
    config_file.write_text(
        """
version: 1
rules:
  severity_overrides:
    aws-access-key: SUPER_CRITICAL
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError) as exc_info:
        load_config(root_dir=tmp_path)
    assert "Invalid severity override" in str(exc_info.value)


def test_unknown_rule_id_generates_warning(tmp_path):
    config_file = tmp_path / ".envguard.yml"
    config_file.write_text(
        """
version: 1
rules:
  disable:
    - totally-nonexistent-rule-id
""",
        encoding="utf-8",
    )

    config = load_config(root_dir=tmp_path)
    assert len(config.warnings) == 1
    assert "totally-nonexistent-rule-id" in config.warnings[0]
