"""Tests for EnvGuard v0.7.0 Git Pre-Push Hook integration."""

import json
from pathlib import Path
import subprocess
import sys
import pytest
from click.testing import CliRunner

from envguard import __version__
from envguard.cli import main
from envguard.exceptions import GitError
from envguard.hook import (
    PRE_PUSH_MARKER_BEGIN,
    PRE_PUSH_MARKER_END,
    install_git_hook,
    install_pre_push_hook,
    is_hook_installed,
)
from envguard.pre_push import (
    ZERO_SHA,
    PrePushRef,
    determine_pushed_commits,
    get_commit_changed_files,
    parse_pre_push_stdin,
    validate_ref_field,
)


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def git_repo(tmp_path):
    """Create a temporary initialized Git repo with git user configured."""
    subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=str(tmp_path), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(tmp_path), capture_output=True, check=True)
    return tmp_path


def test_v070_version():
    """Verify EnvGuard version is 0.7.0."""
    assert __version__ == "0.7.0"


def test_parse_pre_push_stdin_empty():
    """Empty stdin or whitespace returns an empty list."""
    assert parse_pre_push_stdin("") == []
    assert parse_pre_push_stdin("   \n\n  \t ") == []


def test_parse_pre_push_stdin_single_and_multiple():
    """Parse single and multiple ref update lines."""
    line1 = "refs/heads/main 1111111111111111111111111111111111111111 refs/heads/main 2222222222222222222222222222222222222222"
    line2 = f"refs/heads/feature 3333333333333333333333333333333333333333 refs/heads/feature {ZERO_SHA}"
    content = f"{line1}\n{line2}\n"

    refs = parse_pre_push_stdin(content)
    assert len(refs) == 2
    assert refs[0].local_ref == "refs/heads/main"
    assert refs[0].local_sha == "1" * 40
    assert refs[0].remote_ref == "refs/heads/main"
    assert refs[0].remote_sha == "2" * 40
    assert not refs[0].is_create
    assert not refs[0].is_delete
    assert refs[0].ref_name == "main"

    assert refs[1].local_ref == "refs/heads/feature"
    assert refs[1].is_create
    assert not refs[1].is_delete
    assert refs[1].ref_name == "feature"


def test_pre_push_ref_delete():
    """Verify deletion detection for both zero SHA and (delete) ref syntax."""
    del_ref1 = PrePushRef("refs/heads/old", ZERO_SHA, "refs/heads/old", "1" * 40)
    assert del_ref1.is_delete

    del_ref2 = PrePushRef("(delete)", "1" * 40, "refs/heads/old", "2" * 40)
    assert del_ref2.is_delete


def test_validate_ref_field_injection_defense():
    """Leading '-' flags and null bytes must be rejected immediately."""
    with pytest.raises(GitError, match="cannot begin with '-'"):
        validate_ref_field("--output=exploit.txt", "reference")

    with pytest.raises(GitError, match="cannot begin with '-'"):
        validate_ref_field("-v", "reference")

    with pytest.raises(GitError, match="null byte detected"):
        validate_ref_field("refs/heads/main\0exploit", "reference")

    # Safe references should pass
    validate_ref_field("refs/heads/feature/branch-1", "reference")
    validate_ref_field("4b825dc642cb6eb9a060e54bf8d69288fbee4904", "SHA")


def test_install_pre_push_hook(git_repo):
    """Verify install_git_hook creates .git/hooks/pre-push with correct payload."""
    success, msg = install_git_hook("pre-push", repo_path=git_repo)
    assert success
    assert "pre-push" in msg

    hook_file = git_repo / ".git" / "hooks" / "pre-push"
    assert hook_file.is_file()
    content = hook_file.read_text(encoding="utf-8")
    assert PRE_PUSH_MARKER_BEGIN in content
    assert 'envguard pre-push "$@"' in content
    assert PRE_PUSH_MARKER_END in content

    # Check is_hook_installed recognizes it
    assert is_hook_installed(git_repo, "pre-push")
    assert not is_hook_installed(git_repo, "pre-commit")


def test_cli_install_hook_type(runner, git_repo, monkeypatch):
    """Test 'envguard install-hook --type pre-push' via CLI."""
    monkeypatch.chdir(git_repo)
    res = runner.invoke(main, ["install-hook", "--type", "pre-push"])
    assert res.exit_code == 0
    assert is_hook_installed(git_repo, "pre-push")

    # Refresh hook
    res2 = runner.invoke(main, ["install-hook", "--type", "pre-push"])
    assert res2.exit_code == 0
    assert "refreshed" in res2.output.lower() or "installed" in res2.output.lower()


def test_cli_pre_push_clean(runner, git_repo, monkeypatch):
    """Pushing clean commits passes with exit 0."""
    monkeypatch.chdir(git_repo)
    clean_file = git_repo / "clean.py"
    clean_file.write_text("print('Hello safe world')\n", encoding="utf-8")
    subprocess.run(["git", "add", "clean.py"], cwd=str(git_repo), check=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=str(git_repo), check=True)

    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(git_repo), capture_output=True, text=True, check=True).stdout.strip()
    stdin_data = f"refs/heads/main {sha} refs/heads/main {ZERO_SHA}\n"

    res = runner.invoke(main, ["pre-push", "origin"], input=stdin_data)
    assert res.exit_code == 0
    assert "PUSH CHECK PASSED" in res.output or "Clean" in res.output


def test_cli_pre_push_blocking_secret(runner, git_repo, monkeypatch):
    """Pushing commits containing blocking secrets exits 1 with remediation."""
    monkeypatch.chdir(git_repo)
    leak_file = git_repo / "secret.py"
    leak_file.write_text("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8")
    subprocess.run(["git", "add", "secret.py"], cwd=str(git_repo), check=True)
    subprocess.run(["git", "commit", "-m", "Commit with secret"], cwd=str(git_repo), check=True)

    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(git_repo), capture_output=True, text=True, check=True).stdout.strip()
    stdin_data = f"refs/heads/main {sha} refs/heads/main {ZERO_SHA}\n"

    res = runner.invoke(main, ["pre-push", "origin"], input=stdin_data)
    assert res.exit_code == 1
    assert "ENVGUARD BLOCKED PUSH" in res.output
    assert "aws-acce" in res.output
    assert "AKIA" in res.output


def test_cli_pre_push_json_output(runner, git_repo, monkeypatch):
    """envguard pre-push --format json outputs machine-readable schema."""
    monkeypatch.chdir(git_repo)
    clean_file = git_repo / "app.py"
    clean_file.write_text("x = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "app.py"], cwd=str(git_repo), check=True)
    subprocess.run(["git", "commit", "-m", "Clean commit"], cwd=str(git_repo), check=True)

    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(git_repo), capture_output=True, text=True, check=True).stdout.strip()
    stdin_data = f"refs/heads/main {sha} refs/heads/main {ZERO_SHA}\n"

    res = runner.invoke(main, ["pre-push", "origin", "--format", "json"], input=stdin_data)
    assert res.exit_code == 0
    data = json.loads(res.output)
    assert data["command"] == "pre-push"
    assert data["status"] == "passed"
    assert data["commits_scanned"] >= 1
    assert data["push_blocked"] is False


def test_cli_pre_push_delete_branch_exits_cleanly(runner, git_repo, monkeypatch):
    """Deleting a remote branch requires no commit scanning and exits 0."""
    monkeypatch.chdir(git_repo)
    stdin_data = f"refs/heads/deleted {ZERO_SHA} refs/heads/deleted 1111111111111111111111111111111111111111\n"
    res = runner.invoke(main, ["pre-push", "origin"], input=stdin_data)
    assert res.exit_code == 0
    assert "No new commits to scan" in res.output or "PUSH CHECK PASSED" in res.output
