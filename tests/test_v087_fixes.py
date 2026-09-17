"""Tests for EnvGuard v0.8.7 — Remediation Safety Fixes."""

import json
import os
from pathlib import Path
import subprocess
import pytest
from click.testing import CliRunner

from envguard.cli import main
from envguard.remediation import (
    apply_remediation_plan,
    create_remediation_plan,
    ensure_env_in_gitignore,
    inspect_python_assignment,
    is_env_ignored_by_git,
)


def test_bom_prefixed_python_file_safe_parsing(tmp_path):
    """Bug #1: fix can parse and rewrite files containing a UTF-8 BOM without U+FEFF SyntaxError."""
    py_file = tmp_path / "app.py"
    secret_val = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    bom_content = b"\xef\xbb\xbf" + f'API_KEY = "{secret_val}"\n'.encode("utf-8")
    py_file.write_bytes(bom_content)

    # 1. Verify AST inspector directly handles BOM
    is_safe, var_name, skip_reason, needs_import = inspect_python_assignment(
        file_path=py_file,
        line_number=1,
        raw_secret=secret_val,
    )
    assert is_safe is True
    assert var_name == "API_KEY"
    assert skip_reason is None
    assert needs_import is True

    # 2. Verify dry-run preview works with CLI
    runner = CliRunner()
    result_dry = runner.invoke(main, ["fix", str(tmp_path)])
    assert result_dry.exit_code == 0
    assert "DRY-RUN MODE" in result_dry.output
    assert "Proposed Transformations" in result_dry.output
    assert "Manual Remediation Required" not in result_dry.output

    # 3. Verify --apply rewrites file and preserves BOM
    result_apply = runner.invoke(main, ["fix", str(tmp_path), "--apply", "--allow-dirty"])
    assert result_apply.exit_code == 0
    assert "CHANGES APPLIED SUCCESSFULLY" in result_apply.output

    modified_bytes = py_file.read_bytes()
    assert modified_bytes.startswith(b"\xef\xbb\xbf")
    modified_text = modified_bytes.decode("utf-8-sig")
    assert "import os" in modified_text
    assert 'API_KEY = os.environ.get("API_KEY")' in modified_text
    assert secret_val not in modified_text


def test_fix_apply_creates_gitignore_when_missing(tmp_path):
    """Bug #2: fix --apply ensures .env is excluded from Git, creating .gitignore if missing."""
    subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(tmp_path), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(tmp_path), capture_output=True, check=True)

    py_file = tmp_path / "app.py"
    py_file.write_text('SECRET_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"\n', encoding="utf-8")

    gitignore = tmp_path / ".gitignore"
    assert not gitignore.exists()

    runner = CliRunner()
    result = runner.invoke(main, ["fix", str(tmp_path), "--apply", "--allow-dirty"])
    assert result.exit_code == 0

    assert gitignore.is_file()
    gitignore_content = gitignore.read_text(encoding="utf-8")
    assert ".env" in gitignore_content

    proc = subprocess.run(["git", "check-ignore", "-q", ".env"], cwd=str(tmp_path))
    assert proc.returncode == 0

    proc_status = subprocess.run(["git", "status", "--porcelain"], cwd=str(tmp_path), capture_output=True, text=True)
    status_lines = proc_status.stdout.splitlines()
    assert not any(line.strip().endswith(".env") for line in status_lines)


def test_fix_apply_appends_to_existing_gitignore_without_env(tmp_path):
    """Bug #2: fix --apply appends .env to existing .gitignore if .env is not yet ignored."""
    subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(tmp_path), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(tmp_path), capture_output=True, check=True)

    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("*.log\nnode_modules/\n", encoding="utf-8")

    py_file = tmp_path / "app.py"
    py_file.write_text('SECRET_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"\n', encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["fix", str(tmp_path), "--apply", "--allow-dirty"])
    assert result.exit_code == 0

    content = gitignore.read_text(encoding="utf-8")
    assert "*.log" in content
    assert "node_modules/" in content
    assert ".env" in content


def test_fix_rescan_ignores_populated_env_file(tmp_path):
    """Bug #3: .env is excluded from fix scan targets so subsequent runs never propose rewriting .env."""
    py_file = tmp_path / "app.py"
    py_file.write_text('API_KEY = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"\n', encoding="utf-8")

    runner = CliRunner()
    res1 = runner.invoke(main, ["fix", str(tmp_path), "--apply", "--allow-dirty"])
    assert res1.exit_code == 0

    env_file = tmp_path / ".env"
    assert env_file.is_file()
    assert "ghp_1234567890abcdefghijklmnopqrstuvwxyz" in env_file.read_text(encoding="utf-8")

    res2 = runner.invoke(main, ["fix", str(tmp_path), "--format", "json"])
    assert res2.exit_code == 0

    data = json.loads(res2.output)
    assert len(data["safe_actions"]) == 0
    assert len(data["manual_actions"]) == 0
    assert data["summary"]["safe_count"] == 0


def test_fix_explicit_env_file_reports_notice(tmp_path):
    """Bug #3: running 'envguard fix .env' exits cleanly with informative message."""
    env_file = tmp_path / ".env"
    env_file.write_text('API_KEY="ghp_1234567890abcdefghijklmnopqrstuvwxyz"\n', encoding="utf-8")

    runner = CliRunner()
    res = runner.invoke(main, ["fix", str(env_file)])
    assert res.exit_code == 0
    assert "environment configuration file" in res.output.lower()
    assert "transformed as source code" in res.output.lower()
