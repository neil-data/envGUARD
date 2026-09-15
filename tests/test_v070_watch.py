"""Tests for EnvGuard v0.7.0 Filesystem Watch Mode."""

from pathlib import Path
import time
import pytest

from envguard.watch import FileWatcher, run_watch


def test_watcher_initialization_and_snapshot(tmp_path):
    """FileWatcher initializes snapshot and tracks existing non-ignored files."""
    f1 = tmp_path / "main.py"
    f1.write_text("print('start')\n", encoding="utf-8")

    ignored_dir = tmp_path / "node_modules"
    ignored_dir.mkdir()
    (ignored_dir / "pkg.js").write_text("console.log('ignored');\n", encoding="utf-8")

    watcher = FileWatcher(target_path=tmp_path, debounce_delay=0.1, poll_interval=0.05)
    watcher.initialize_snapshot()

    assert "main.py" in watcher.snapshot
    assert "node_modules/pkg.js" not in watcher.snapshot


def test_watcher_detects_modification_with_debounce(tmp_path):
    """FileWatcher detects changes only after debounce delay has passed."""
    target_file = tmp_path / "config.py"
    target_file.write_text("VAL = 1\n", encoding="utf-8")

    watcher = FileWatcher(target_path=tmp_path, debounce_delay=0.15, poll_interval=0.05)
    watcher.initialize_snapshot()

    # Initially no changes
    assert watcher.check_for_changes() == []

    # Modify file
    time.sleep(0.05)
    target_file.write_text("VAL = 2\n", encoding="utf-8")

    # Immediate check: change is detected but pending (debounce not reached)
    ready1 = watcher.check_for_changes()
    assert "config.py" in watcher.pending_changes

    # Wait past debounce window
    time.sleep(0.2)
    ready2 = watcher.check_for_changes()
    assert "config.py" in ready2
    assert "config.py" not in watcher.pending_changes


def test_watcher_detects_secret_on_file(tmp_path):
    """FileWatcher.scan_file_rel detects secrets in modified file."""
    gh_token = "gh" + "p_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    secret_file = tmp_path / "keys.py"
    secret_file.write_text(f"GITHUB_TOKEN = '{gh_token}'\n", encoding="utf-8")

    watcher = FileWatcher(target_path=tmp_path)
    findings = watcher.scan_file_rel("keys.py")

    assert len(findings) >= 1
    assert any("github" in f.rule_id.lower() for f in findings)
    assert findings[0].file_path == "keys.py"
    assert findings[0].line_number == 1
    assert findings[0].column >= 1


def test_watcher_ignores_builtin_dirs(tmp_path):
    """Builtin directories like .git and venv are pruned during scan_tree."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text("[core]\n", encoding="utf-8")

    venv_dir = tmp_path / "venv"
    venv_dir.mkdir()
    (venv_dir / "lib.py").write_text("pass\n", encoding="utf-8")

    watcher = FileWatcher(target_path=tmp_path)
    tree = watcher.scan_tree()

    for path in tree:
        assert not path.startswith(".git")
        assert not path.startswith("venv")


def test_watcher_handles_file_deletion(tmp_path):
    """Deleting a file removes it from snapshot and does not throw errors."""
    f = tmp_path / "temp.txt"
    f.write_text("temp", encoding="utf-8")

    watcher = FileWatcher(target_path=tmp_path, debounce_delay=0.05)
    watcher.initialize_snapshot()
    assert "temp.txt" in watcher.snapshot

    f.unlink()
    ready = watcher.check_for_changes()
    assert "temp.txt" not in watcher.snapshot
    assert "temp.txt" not in ready


def test_watcher_run_single_iteration(tmp_path):
    """run(max_iterations=1) executes one loop and terminates cleanly."""
    f = tmp_path / "app.py"
    f.write_text("print(1)\n", encoding="utf-8")

    watcher = FileWatcher(target_path=tmp_path, debounce_delay=0.05, poll_interval=0.01)
    watcher.run(max_iterations=1)
    assert "app.py" in watcher.snapshot
