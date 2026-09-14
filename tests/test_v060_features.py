"""Test suite for EnvGuard v0.6.0:
- Organization Policy (.envguard-org.yml / .envguard-org.yaml)
- Fail-stop security floor enforcement (block_on & disabled_rules)
- Clear attribution of blocking policy (local vs organization vs composite)
- Multi-repository scanning (envguard scan --repos)
- Tolerant execution, argument injection protection, and multi-repo reporting
- Integration with status and doctor commands
"""

import json
import os
from pathlib import Path
import subprocess
import pytest
from click.testing import CliRunner

from envguard import __version__
from envguard.cli import main
from envguard.config import (
    EnvGuardConfig,
    find_config_file,
    find_org_config_file,
    load_config,
)
from envguard.diagnostics import run_diagnostics
from envguard.exceptions import ConfigurationError, ScanError
from envguard.multi_repo import (
    MultiRepoScanResult,
    RepoScanResult,
    parse_repo_targets,
    scan_multiple_repositories,
    validate_repo_path,
)
from envguard.scanner import ScanFinding, determine_blocking, scan_directory


@pytest.fixture
def runner():
    return CliRunner()


def test_v060_version_bump(runner):
    """Verify EnvGuard version is 0.6.0."""
    assert __version__ == "0.6.0"
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.6.0" in result.output


# ---------------------------------------------------------------------------
# Organization Policy & Fail-stop Security Floor Tests
# ---------------------------------------------------------------------------

def test_org_policy_loading_and_fallback(tmp_path):
    """Verify loading organization policy when present, and safe fallback when absent."""
    # Absent
    cfg = load_config(root_dir=tmp_path)
    assert cfg.org_config is None
    assert cfg.org_config_path is None

    # Present
    org_file = tmp_path / ".envguard-org.yml"
    org_file.write_text(
        "version: 1\n"
        "scan:\n"
        "  block_on:\n"
        "    - HIGH\n",
        encoding="utf-8",
    )
    loaded = load_config(root_dir=tmp_path)
    assert loaded.org_config is not None
    assert loaded.org_config_path == org_file
    assert "HIGH" in loaded.block_on


def test_org_policy_strict_validation(tmp_path):
    """Organization policy must use same strict validation as local config."""
    org_file = tmp_path / ".envguard-org.yml"
    org_file.write_text(
        "version: 1\n"
        "scan:\n"
        "  block_on:\n"
        "    - INVALID_SEVERITY\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError) as exc:
        load_config(root_dir=tmp_path)
    assert "INVALID_SEVERITY" in str(exc.value)


def test_fail_stop_weaken_block_on(tmp_path):
    """Local config cannot weaken block_on required by organization policy."""
    org_file = tmp_path / ".envguard-org.yml"
    org_file.write_text(
        "version: 1\n"
        "scan:\n"
        "  block_on:\n"
        "    - HIGH\n"
        "    - MEDIUM\n",
        encoding="utf-8",
    )
    local_file = tmp_path / ".envguard.yml"
    # Local only blocks LOW, omitting HIGH and MEDIUM required by org
    local_file.write_text(
        "version: 1\n"
        "scan:\n"
        "  block_on:\n"
        "    - LOW\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError) as exc:
        load_config(root_dir=tmp_path)
    assert "cannot weaken 'block_on' policy" in str(exc.value)
    assert "HIGH" in str(exc.value)


def test_allow_strengthen_block_on(tmp_path):
    """Local config CAN strengthen block_on by adding additional severities."""
    org_file = tmp_path / ".envguard-org.yml"
    org_file.write_text(
        "version: 1\n"
        "scan:\n"
        "  block_on:\n"
        "    - HIGH\n",
        encoding="utf-8",
    )
    local_file = tmp_path / ".envguard.yml"
    # Local adds MEDIUM
    local_file.write_text(
        "version: 1\n"
        "scan:\n"
        "  block_on:\n"
        "    - HIGH\n"
        "    - MEDIUM\n",
        encoding="utf-8",
    )

    cfg = load_config(root_dir=tmp_path)
    assert set(cfg.block_on) == {"HIGH", "MEDIUM"}
    assert set(cfg.local_block_on) == {"HIGH", "MEDIUM"}
    assert set(cfg.org_config.block_on) == {"HIGH"}


def test_fail_stop_disable_org_enforced_rule(tmp_path):
    """Local config cannot disable a rule enforced by organization policy."""
    org_file = tmp_path / ".envguard-org.yml"
    org_file.write_text(
        "version: 1\n"
        "scan:\n"
        "  block_on:\n"
        "    - HIGH\n",
        encoding="utf-8",
    )
    local_file = tmp_path / ".envguard.yml"
    # Local attempts to disable aws-access-key
    local_file.write_text(
        "version: 1\n"
        "rules:\n"
        "  disabled:\n"
        "    - aws-access-key\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError) as exc:
        load_config(root_dir=tmp_path)
    assert "cannot disable rule 'aws-access-key'" in str(exc.value)
    assert "enforced by organization policy" in str(exc.value)


def test_attribution_determination():
    """Verify determine_blocking returns accurate attribution strings."""
    # Both block
    assert determine_blocking("HIGH", {"HIGH", "MEDIUM"}, {"HIGH"}) == "organization & local policy"
    # Org only blocks
    assert determine_blocking("HIGH", {"MEDIUM"}, {"HIGH"}) == "organization policy"
    # Local only blocks
    assert determine_blocking("MEDIUM", {"MEDIUM"}, {"HIGH"}) == "local policy"
    # Neither blocks
    assert determine_blocking("LOW", {"MEDIUM"}, {"HIGH"}) is None


# ---------------------------------------------------------------------------
# Diagnostics & Status Integration Tests
# ---------------------------------------------------------------------------

def test_doctor_diagnostics_org_policy(tmp_path):
    """Verify envguard doctor check 5b reports organization policy status."""
    # Absent
    results = run_diagnostics(tmp_path)
    org_diag = next(d for d in results.checks if d.name == "Organization Policy")
    assert org_diag.status == "PASS"
    assert "no organization policy" in org_diag.details.lower()

    # Valid
    org_file = tmp_path / ".envguard-org.yml"
    org_file.write_text("version: 1\nscan:\n  block_on:\n    - HIGH\n", encoding="utf-8")
    results = run_diagnostics(tmp_path)
    org_diag = next(d for d in results.checks if d.name == "Organization Policy")
    assert org_diag.status == "PASS"
    assert "active" in org_diag.details.lower()

    # Invalid
    org_file.write_text("version: 1\nscan:\n  block_on:\n    - BOGUS\n", encoding="utf-8")
    results = run_diagnostics(tmp_path)
    org_diag = next(d for d in results.checks if d.name == "Organization Policy")
    assert org_diag.status == "ERROR"


def test_status_json_org_policy(tmp_path, runner):
    """Verify status command includes organization_policy in JSON output."""
    org_file = tmp_path / ".envguard-org.yml"
    org_file.write_text("version: 1\nscan:\n  block_on:\n    - HIGH\n", encoding="utf-8")

    orig = os.getcwd()
    os.chdir(tmp_path)
    try:
        result = runner.invoke(main, ["status", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "organization_policy" in data["checks"]
        assert data["checks"]["organization_policy"]["present"] is True
        assert data["checks"]["organization_policy"]["status"] == "ACTIVE"
        assert "HIGH" in data["checks"]["organization_policy"]["block_on"]
    finally:
        os.chdir(orig)


# ---------------------------------------------------------------------------
# Multi-Repository Scanning & Validation Tests
# ---------------------------------------------------------------------------

def test_validate_repo_path_injection_defense():
    """validate_repo_path must reject leading hyphens, empty strings, and null bytes."""
    with pytest.raises(ScanError) as exc:
        validate_repo_path("--output=pwned.txt")
    assert "cannot begin with '-'" in str(exc.value)

    with pytest.raises(ScanError) as exc:
        validate_repo_path("-rf")
    assert "cannot begin with '-'" in str(exc.value)

    with pytest.raises(ScanError) as exc:
        validate_repo_path("  ")
    assert "cannot be empty" in str(exc.value)

    with pytest.raises(ScanError) as exc:
        validate_repo_path("repo\0name")
    assert "contains null byte" in str(exc.value)


def test_parse_repo_targets():
    """parse_repo_targets supports comma-separated strings and multiple arguments."""
    targets = parse_repo_targets(["./repo-a, ./repo-b", "./repo-c"])
    assert len(targets) == 3
    assert targets[0] == Path("./repo-a")
    assert targets[1] == Path("./repo-b")
    assert targets[2] == Path("./repo-c")


def test_multi_repo_scanning_clean(tmp_path, runner):
    """Multi-repo scan across clean repositories exits 0."""
    repo1 = tmp_path / "repo1"
    repo1.mkdir()
    (repo1 / "index.js").write_text("console.log('hello');", encoding="utf-8")

    repo2 = tmp_path / "repo2"
    repo2.mkdir()
    (repo2 / "app.py").write_text("print('clean code')", encoding="utf-8")

    result = runner.invoke(main, ["scan", "--repos", f"{repo1},{repo2}"])
    assert result.exit_code == 0
    assert "repo1" in result.output
    assert "repo2" in result.output
    assert "Passed" in result.output


def test_multi_repo_scanning_with_findings_and_attribution(tmp_path, runner):
    """Multi-repo scan detects findings, tags repository, assigns blocked_by, and exits 1."""
    repo1 = tmp_path / "repo1"
    repo1.mkdir()
    (repo1 / "clean.py").write_text("x = 1\n", encoding="utf-8")

    repo2 = tmp_path / "repo2"
    repo2.mkdir()
    # Add org policy to repo2 requiring HIGH
    (repo2 / ".envguard-org.yml").write_text("version: 1\nscan:\n  block_on:\n    - HIGH\n", encoding="utf-8")
    # Add AWS secret in repo2
    (repo2 / "secret.env").write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")

    result = runner.invoke(main, ["scan", "--repos", f"{repo1},{repo2}", "--format", "json"])
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["multi_repo"] is True
    assert data["summary"]["total_repositories"] == 2
    assert data["summary"]["passed_repositories"] == 1
    assert data["summary"]["failed_repositories"] == 1

    # Check finding fields
    assert len(data["findings"]) == 1
    finding = data["findings"][0]
    assert finding["repository"] == "repo2"
    assert finding["blocked_by"] in ("organization policy", "organization & local policy")


def test_multi_repo_partial_failure_isolation(tmp_path, runner):
    """A missing or invalid repo path produces status 'error' for that repo without aborting others."""
    clean_repo = tmp_path / "clean_repo"
    clean_repo.mkdir()
    (clean_repo / "main.py").write_text("print('hello')", encoding="utf-8")

    missing_repo = tmp_path / "does_not_exist"

    result = runner.invoke(main, ["scan", "--repos", f"{clean_repo},{missing_repo}", "--format", "json"])
    # Exit code 2 because there were execution errors and no blocking findings
    assert result.exit_code == 2
    data = json.loads(result.output)
    assert data["summary"]["total_repositories"] == 2
    assert data["summary"]["passed_repositories"] == 1
    assert data["summary"]["error_repositories"] == 1

    repos_by_name = {r["name"]: r for r in data["repositories"]}
    assert repos_by_name["clean_repo"]["status"] == "passed"
    assert repos_by_name["does_not_exist"]["status"] == "error"
    assert "does not exist" in repos_by_name["does_not_exist"]["error"]


def test_multi_repo_sarif_output(tmp_path, runner):
    """Multi-repo SARIF report prefixes file URIs with repository name."""
    repo = tmp_path / "my_project"
    repo.mkdir()
    (repo / "creds.py").write_text("KEY=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")

    sarif_file = tmp_path / "results.sarif"
    result = runner.invoke(main, ["scan", "--repos", str(repo), "--format", "sarif", "--output", str(sarif_file)])
    assert result.exit_code == 1
    assert sarif_file.is_file()

    sarif_data = json.loads(sarif_file.read_text(encoding="utf-8"))
    results = sarif_data["runs"][0]["results"]
    assert len(results) >= 1
    uri = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.startswith("my_project/")
