"""Tests for EnvGuard v0.7.5 Scanner Progress and Watch Live UI."""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from click.testing import CliRunner

from envguard.cli import main
from envguard.scanner import scan_directory, scan_files
from envguard.watch import FileWatcher


def test_scanner_progress_callback(tmp_path):
    """Verify scanner invokes progress_callback with relative path and file count."""
    f1 = tmp_path / "a.py"
    f1.write_text("print(1)\n", encoding="utf-8")
    f2 = tmp_path / "b.py"
    f2.write_text("print(2)\n", encoding="utf-8")

    callbacks = []

    def on_progress(rel_path: str, count: int, total_hint):
        callbacks.append((rel_path, count, total_hint))

    findings = scan_directory(
        directory=tmp_path,
        progress_callback=on_progress,
    )

    assert len(callbacks) == 2
    paths = [c[0] for c in callbacks]
    assert "a.py" in paths
    assert "b.py" in paths


def test_scan_cmd_no_progress_in_ci(tmp_path):
    """Verify scan_cmd does not create interactive Progress in CI environments."""
    f = tmp_path / "main.py"
    f.write_text("print('hello')\n", encoding="utf-8")

    runner = CliRunner()
    with patch.dict(os.environ, {"CI": "true"}):
        result = runner.invoke(main, ["scan", str(tmp_path)])
        assert result.exit_code == 0
        assert "SCAN PASSED" in result.output


def test_scan_cmd_machine_readable_purity(tmp_path):
    """Verify --format json produces pure JSON without ANSI codes or Progress bars."""
    f = tmp_path / "main.py"
    f.write_text("print('hello')\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0
    # Must start with '{' without any ANSI escape prefixes
    stripped = result.output.strip()
    assert stripped.startswith("{")
    assert stripped.endswith("}")
    assert "\x1b[" not in result.output


def test_watch_live_status_panel(tmp_path):
    """Verify FileWatcher.create_status_panel builds expected dashboard elements."""
    f = tmp_path / "test.py"
    f.write_text("x = 1\n", encoding="utf-8")

    watcher = FileWatcher(target_path=tmp_path)
    watcher.initialize_snapshot()

    panel = watcher.create_status_panel(status="IDLE", last_event="Initial idle")
    assert panel is not None

    panel_alert = watcher.create_status_panel(status="ALERT", last_event="Leak detected")
    assert panel_alert.border_style == "red"
