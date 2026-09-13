"""Regression tests for EnvGuard v0.3.1 Configuration Stability & Bug Fix Release."""

import json
from pathlib import Path
import subprocess
import sys
import pytest
from click.testing import CliRunner

from envguard import __version__
from envguard.cli import main
from envguard.config import EnvGuardConfig, load_config
from envguard.diagnostics import run_diagnostics
from envguard.exceptions import ConfigurationError
from envguard.initializer import init_project
from envguard.reporter import render_check_json, render_scan_json
from envguard.scanner import ScanFinding, compute_fingerprint, scan_text


def test_v031_version_strings():
    """Verify version is consistent across package and CLI."""
    assert __version__ >= "0.3.1"
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert f"EnvGuard version {__version__}" in result.output


def test_empty_yaml_values_normalized(tmp_path):
    """YAML empty keys (which parse to None) must normalize safely to empty collections."""
    config_file = tmp_path / ".envguard.yml"
    config_file.write_text(
        """# EnvGuard Configuration
version: 1

scan:
  max_file_size_mb: 5.0
  block_on:
    - 'HIGH'
    - 'MEDIUM'
  respect_gitignore: true

exclude:

rules:
  disabled:
  severity_overrides:

reporting:
  color: true
  show_fingerprints: false
""",
        encoding="utf-8",
    )

    config = load_config(root_dir=tmp_path)
    assert isinstance(config, EnvGuardConfig)
    assert config.exclude == []
    assert config.disabled_rules == set()
    assert config.severity_overrides == {}
    assert config.block_on == ["HIGH", "MEDIUM"]


def test_comment_only_yaml_values_normalized(tmp_path):
    """YAML comment-only keys must normalize safely to empty collections."""
    config_file = tmp_path / ".envguard.yml"
    config_file.write_text(
        """# EnvGuard Configuration
version: 1

rules:
  disabled:
    # - 'generic-credential'
  severity_overrides:
    # 'generic-secret': 'LOW'
""",
        encoding="utf-8",
    )

    config = load_config(root_dir=tmp_path)
    assert isinstance(config, EnvGuardConfig)
    assert config.disabled_rules == set()
    assert config.severity_overrides == {}


def test_explicit_empty_collections(tmp_path):
    """Canonical starter format with [] and {} must load cleanly."""
    config_file = tmp_path / ".envguard.yml"
    config_file.write_text(
        """# EnvGuard Configuration
version: 1

scan:
  max_file_size_mb: 5.0
  block_on:
    - HIGH
    - MEDIUM
  respect_gitignore: true

exclude: []

rules:
  disabled: []
  severity_overrides: {}

reporting:
  color: true
  show_fingerprints: false
""",
        encoding="utf-8",
    )

    config = load_config(root_dir=tmp_path)
    assert isinstance(config, EnvGuardConfig)
    assert config.exclude == []
    assert config.disabled_rules == set()
    assert config.severity_overrides == {}
    assert config.block_on == ["HIGH", "MEDIUM"]


def test_populated_rules_and_overrides(tmp_path):
    """Valid populated rules and overrides must be parsed accurately."""
    config_file = tmp_path / ".envguard.yml"
    config_file.write_text(
        """# EnvGuard Configuration
version: 1

rules:
  disabled:
    - generic-credential
  severity_overrides:
    generic-secret: LOW
""",
        encoding="utf-8",
    )

    config = load_config(root_dir=tmp_path)
    assert "generic-credential" in config.disabled_rules
    assert config.severity_overrides.get("generic-secret") == "LOW"


def test_invalid_disabled_type_raises_configuration_error(tmp_path):
    """Invalid collection types must raise ConfigurationError with diagnostic fields."""
    config_file = tmp_path / ".envguard.yml"
    config_file.write_text(
        """version: 1
rules:
  disabled: "generic-secret"
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError) as exc_info:
        load_config(root_dir=tmp_path)

    err = exc_info.value
    assert "rules.disabled must be a list" in str(err)
    assert err.field == "rules.disabled"
    assert err.expected == "list"
    assert err.received == "str"


def test_invalid_overrides_type_raises_configuration_error(tmp_path):
    """Invalid severity_overrides type (e.g. list instead of dict) must raise ConfigurationError."""
    config_file = tmp_path / ".envguard.yml"
    config_file.write_text(
        """version: 1
rules:
  severity_overrides:
    - invalid
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError) as exc_info:
        load_config(root_dir=tmp_path)

    err = exc_info.value
    assert "rules.severity_overrides must be a dictionary" in str(err)
    assert err.field == "rules.severity_overrides"
    assert err.expected == "dictionary"
    assert err.received == "list"


def test_init_canonical_config_and_round_trip(tmp_path):
    """'envguard init' must generate canonical config that passes self-validation and doctor."""
    result = init_project(tmp_path)
    assert result.config_created is True
    assert result.ignore_created is True

    # Loading the generated config must succeed immediately
    cfg = load_config(root_dir=tmp_path)
    assert cfg.version == 1
    assert cfg.exclude == []
    assert cfg.disabled_rules == set()
    assert cfg.severity_overrides == {}

    # Doctor check on this config must report PASS
    diag = run_diagnostics(tmp_path)
    config_check = next((c for c in diag.checks if c.name == "Repository Config"), None)
    assert config_check is not None
    assert config_check.status == "PASS"


def test_status_fails_on_invalid_config_without_silent_fallback(tmp_path):
    """'envguard status' must exit with code 2 on broken .envguard.yml and never fall back silently."""
    config_file = tmp_path / ".envguard.yml"
    config_file.write_text(
        """version: 1
rules:
  severity_overrides:
    - invalid_list_not_dict
""",
        encoding="utf-8",
    )

    runner = CliRunner()
    with runner.isolated_filesystem():
        Path(".envguard.yml").write_text(
            """version: 1
rules:
  severity_overrides:
    - invalid_list_not_dict
""",
            encoding="utf-8",
        )
        result = runner.invoke(main, ["status"])
        assert result.exit_code == 2
        assert "CONFIGURATION ERROR" in result.output.upper()


def test_scan_and_check_fail_with_code_2_on_invalid_config():
    """'scan' and 'check' must exit with code 2 on invalid configuration."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path(".envguard.yml").write_text(
            """version: 1
rules:
  disabled: "not_a_list"
""",
            encoding="utf-8",
        )
        scan_res = runner.invoke(main, ["scan"])
        assert scan_res.exit_code == 2

        check_res = runner.invoke(main, ["check"])
        assert check_res.exit_code == 2


def test_rules_list_succeeds_even_with_broken_project_config():
    """'envguard rules list' should list built-in rules even if local .envguard.yml is invalid."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path(".envguard.yml").write_text(
            """version: 1
rules:
  disabled: "broken_value"
""",
            encoding="utf-8",
        )
        result = runner.invoke(main, ["rules", "list"])
        assert result.exit_code == 0
        assert "Detection Rules" in result.output

        # JSON format should also succeed
        json_result = runner.invoke(main, ["rules", "list", "--format", "json"])
        assert json_result.exit_code == 0
        data = json.loads(json_result.output)
        assert data["command"] == "rules"
        assert len(data["rules"]) > 0


def test_sha256_fingerprint_hex_length_and_characters():
    """Verify SHA-256 fingerprint hash is exactly 64 lowercase hexadecimal characters."""
    raw_secret = "AKIAIOSFODNN7EXAMPLE"
    file_path = "src/config/aws.py"
    rule_id = "aws-access-key"

    fp = compute_fingerprint(rule_id, file_path, raw_secret)
    assert fp.startswith("sha256:")

    # Extract the hex digest portion
    digest = fp.split("sha256:", 1)[1]
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)

    # Scan finding property
    finding = ScanFinding(
        rule_id=rule_id,
        rule_name="AWS Access Key",
        severity="HIGH",
        file_path=file_path,
        line_number=10,
        raw_value=raw_secret,
        masked_value="AKIA************MPLE",
        fingerprint=fp,
    )
    assert finding.fingerprint_hash == digest
    assert len(finding.fingerprint_hash) == 64
    assert all(c in "0123456789abcdef" for c in finding.fingerprint_hash)


def test_detection_signals_not_emitted_when_empty(capsys):
    """Ensure dead empty 'detection_signals: []' metadata is omitted from JSON output."""
    finding = ScanFinding(
        rule_id="stripe-secret-key",
        rule_name="Stripe Secret API Key",
        severity="HIGH",
        file_path="app/keys.py",
        line_number=5,
        raw_value="sk_live_1234567890abcdef",
        masked_value="sk_live_****************",
        fingerprint="sha256:" + "a" * 64,
        detection_signals=[],  # empty
    )

    render_scan_json([finding])
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert "findings" in data
    assert len(data["findings"]) == 1
    # detection_signals should NOT be present when empty
    assert "detection_signals" not in data["findings"][0]

    render_check_json([finding], [])
    captured_check = capsys.readouterr().out
    check_data = json.loads(captured_check)
    assert "detection_signals" not in check_data["findings"][0]


def test_verbose_mode_shows_structured_diagnostics_without_traceback():
    """--verbose on ConfigurationError must show structured Field/Expected/Received details without raw python traceback."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path(".envguard.yml").write_text(
            """version: 1
rules:
  severity_overrides:
    - invalid_list
""",
            encoding="utf-8",
        )
        result = runner.invoke(main, ["-v", "scan"])
        assert result.exit_code == 2
        # Must show structured fields
        assert "Field:" in result.output
        assert "rules.severity_overrides" in result.output
        assert "Expected:" in result.output
        assert "dictionary" in result.output
        assert "Received:" in result.output
        assert "list" in result.output
        # Must NOT dump raw python traceback
        assert "Traceback (most recent call last):" not in result.output
