"""Tests for performance controls, file safety limits, and exit code contract."""

from pathlib import Path
from click.testing import CliRunner
import pytest

from envguard.cli import main
from envguard.patterns import load_default_patterns
from envguard.scanner import scan_directory


def test_large_file_is_skipped(tmp_path):
    patterns = load_default_patterns()

    # Create a small file with a secret
    small_file = tmp_path / "small.py"
    small_file.write_text("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8")

    # Create a large file (> 1 MB limit for this test) with a secret
    large_file = tmp_path / "huge.txt"
    # Write 1.5MB of padding plus a secret
    large_file.write_text("x" * (1024 * 1024 + 500000) + "\nAWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8")

    verbose_log = []
    # Test with 1 MB max size limit
    max_bytes = 1 * 1024 * 1024
    findings = scan_directory(
        tmp_path,
        patterns=patterns,
        max_file_size_bytes=max_bytes,
        verbose_log=verbose_log,
    )

    found_files = {f.file_path for f in findings}
    assert "small.py" in found_files
    assert "huge.txt" not in found_files
    assert any("oversized" in log for log in verbose_log)


def test_exit_code_contract():
    runner = CliRunner()

    # 1. Invalid CLI usage must exit with 3
    result_invalid = runner.invoke(main, ["scan", "--invalid-unknown-option-xyz"])
    assert result_invalid.exit_code == 3

    # 2. Help exits with 0
    result_help = runner.invoke(main, ["--help"])
    assert result_help.exit_code == 0

    # 3. Version exits with 0
    result_version = runner.invoke(main, ["--version"])
    assert result_version.exit_code == 0
    assert "0.2.5" in result_version.output
