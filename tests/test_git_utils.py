"""Tests for safe Git integration utilities (envguard/git_utils.py)."""

from pathlib import Path
import subprocess
import pytest

from envguard.exceptions import GitError
from envguard.git_utils import (
    get_changed_files,
    get_default_base_branch,
    get_git_root,
    get_staged_files,
    is_git_repository,
    run_git,
)


@pytest.fixture
def temp_git_repo(tmp_path):
    """Fixture providing an initialized Git repository with initial commit."""
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test Runner"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True, capture_output=True)

    # Create initial file & commit on main
    init_file = repo / "README.md"
    init_file.write_text("# Test Repo\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "Initial commit"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "branch", "-M", "main"], check=True, capture_output=True)

    return repo


def test_is_git_repository(temp_git_repo, tmp_path):
    """Verify is_git_repository returns True for git repos and False for regular dirs."""
    assert is_git_repository(temp_git_repo)
    sub = temp_git_repo / "subdir"
    sub.mkdir()
    assert is_git_repository(sub)

    non_git = tmp_path / "plain_dir"
    non_git.mkdir()
    assert not is_git_repository(non_git)


def test_get_git_root(temp_git_repo):
    """Verify get_git_root resolves the repository toplevel."""
    root = get_git_root(temp_git_repo)
    assert root is not None
    assert root.resolve() == temp_git_repo.resolve()

    sub = temp_git_repo / "deep" / "folder"
    sub.mkdir(parents=True)
    assert get_git_root(sub).resolve() == temp_git_repo.resolve()


def test_get_staged_files(temp_git_repo):
    """Verify staged files are detected in the Git index."""
    staged_file = temp_git_repo / "staged.txt"
    staged_file.write_text("content\n", encoding="utf-8")

    # Before staging
    assert len(get_staged_files(temp_git_repo)) == 0

    # After staging
    subprocess.run(["git", "-C", str(temp_git_repo), "add", "staged.txt"], check=True, capture_output=True)
    staged = get_staged_files(temp_git_repo)
    assert len(staged) == 1
    assert staged[0].name == "staged.txt"


def test_get_changed_files_between_commits(temp_git_repo):
    """Verify get_changed_files detects modified and newly added files relative to base."""
    # Create a feature branch
    subprocess.run(["git", "-C", str(temp_git_repo), "checkout", "-b", "feature"], check=True, capture_output=True)

    # Add a new file on feature
    new_file = temp_git_repo / "feature.py"
    new_file.write_text("print('feature')\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(temp_git_repo), "add", "feature.py"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(temp_git_repo), "commit", "-m", "Add feature file"], check=True, capture_output=True)

    changed = get_changed_files(base="main", head="HEAD", repo_path=temp_git_repo)
    assert len(changed) == 1
    assert changed[0].name == "feature.py"


def test_get_default_base_branch(temp_git_repo):
    """Verify default base branch detection resolves main."""
    base = get_default_base_branch(temp_git_repo)
    assert base == "main"


def test_non_git_error_handling(tmp_path):
    """Verify GitError is raised when trying to diff on a non-git directory."""
    non_git = tmp_path / "not_a_repo"
    non_git.mkdir()
    with pytest.raises(GitError) as exc_info:
        get_changed_files("main", "HEAD", repo_path=non_git)
    assert "Unable to compare Git references" in str(exc_info.value)
