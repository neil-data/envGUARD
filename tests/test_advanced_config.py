"""Unit tests for advanced_detection configuration loading and validation."""

import pytest
from envguard.config import load_config
from envguard.exceptions import ConfigurationError


def test_valid_advanced_detection_config(tmp_path):
    cfg_file = tmp_path / ".envguard.yml"
    cfg_file.write_text("""
version: 1
advanced_detection:
  entropy:
    enabled: true
    min_length: 20
    threshold: 4.2
  jwt:
    enabled: false
  context_analysis:
    enabled: true
""", encoding="utf-8")

    config = load_config(root_dir=tmp_path)
    assert config.advanced_detection.entropy_enabled is True
    assert config.advanced_detection.entropy_min_length == 20
    assert config.advanced_detection.entropy_threshold == 4.2
    assert config.advanced_detection.jwt_enabled is False
    assert config.advanced_detection.context_enabled is True


def test_invalid_entropy_threshold_out_of_bounds(tmp_path):
    cfg_file = tmp_path / ".envguard.yml"
    cfg_file.write_text("""
version: 1
advanced_detection:
  entropy:
    threshold: 9.5
""", encoding="utf-8")

    with pytest.raises(ConfigurationError) as exc_info:
        load_config(root_dir=tmp_path)
    assert "entropy.threshold" in str(exc_info.value)


def test_invalid_entropy_min_length_negative(tmp_path):
    cfg_file = tmp_path / ".envguard.yml"
    cfg_file.write_text("""
version: 1
advanced_detection:
  entropy:
    min_length: -5
""", encoding="utf-8")

    with pytest.raises(ConfigurationError) as exc_info:
        load_config(root_dir=tmp_path)
    assert "entropy.min_length" in str(exc_info.value)


def test_invalid_advanced_detection_type(tmp_path):
    cfg_file = tmp_path / ".envguard.yml"
    cfg_file.write_text("""
version: 1
advanced_detection: "not_a_dictionary"
""", encoding="utf-8")

    with pytest.raises(ConfigurationError) as exc_info:
        load_config(root_dir=tmp_path)
    assert "advanced_detection" in str(exc_info.value)
