"""Tests verifying fixes for the 7 bugs addressed in EnvGuard v0.4.2."""

import json
from pathlib import Path
from click.testing import CliRunner
import pytest

from envguard import __version__
from envguard.baseline import create_baseline
from envguard.cli import main
from envguard.detectors.entropy_detector import detect_entropy_candidates, is_code_expression
from envguard.detectors.scoring import AdvancedDetectionConfig, DetectionCandidate, score_candidate
from envguard.diagnostics import run_diagnostics
from envguard.patterns import load_default_patterns
from envguard.scanner import scan_directory, scan_lines, scan_text


def test_v042_version():
    """Verify version bumped to 0.4.2."""
    assert __version__ == "0.4.2"
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.4.2" in result.output


def test_bug_1_doctor_git_far_above(tmp_path, monkeypatch):
    """Bug #1: doctor warns when Git root is far above or at user home."""
    # Test user home warning
    fake_home = tmp_path / "home_dir"
    fake_home.mkdir()
    import subprocess
    subprocess.run(["git", "init", str(fake_home)], capture_output=True)
    sub_dir = fake_home / "project" / "sub"
    sub_dir.mkdir(parents=True)

    monkeypatch.setattr(Path, "home", lambda: fake_home)

    report = run_diagnostics(sub_dir)
    git_checks = [c for c in report.checks if c.name == "Git Repository"]
    assert len(git_checks) == 1
    assert git_checks[0].status == "WARNING"
    assert "user home directory" in git_checks[0].details or "far above" in git_checks[0].details


def test_bug_2_check_json_command_label(tmp_path):
    """Bug #2: check --format json must output command: 'check', not 'diff'."""
    runner = CliRunner()
    non_git_dir = tmp_path / "not_git"
    non_git_dir.mkdir()

    with runner.isolated_filesystem(temp_dir=non_git_dir):
        result = runner.invoke(main, ["check", "--format", "json"])
        # Should exit with code 2 on git error
        assert result.exit_code == 2
        data = json.loads(result.output)
        assert data["command"] == "check"
        assert data["status"] == "error"
        assert "not a Git repository" in data["error"]


def test_bug_3_scan_verbose_directory_pruning(tmp_path):
    """Bug #3: verbose scan prunes ignored directories instead of logging thousands of files."""
    # Create an ignored directory with many files
    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    for i in range(20):
        (node_modules / f"pkg_{i}.js").write_text("console.log('test');\n", encoding="utf-8")

    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("node_modules/\n", encoding="utf-8")

    patterns = load_default_patterns()
    verbose_log = []
    stats = {}

    findings = scan_directory(
        directory=tmp_path,
        patterns=patterns,
        respect_gitignore=True,
        verbose_log=verbose_log,
        stats=stats,
    )

    assert len(findings) == 0
    # node_modules should be pruned at directory level
    assert any("Skipped directory node_modules/" in entry for entry in verbose_log)
    # Individual files inside node_modules should NOT be logged separately
    assert not any("Skipped node_modules/pkg_" in entry for entry in verbose_log)


def test_bug_4_entropy_detector_ignores_code_expressions():
    """Bug #4: expressions like os.environ.get, re.compile, and function calls are ignored."""
    cfg = AdvancedDetectionConfig(entropy_enabled=True, entropy_threshold=3.5, entropy_min_length=15)

    assert is_code_expression("os.environ.get('MY_API_KEY')")
    assert is_code_expression("os.getenv('SECRET_TOKEN')")
    assert is_code_expression("re.compile(r'^[A-Z0-9]{20}$')")
    assert is_code_expression("get_credentials_from_vault()")
    assert is_code_expression("request.headers.get('Authorization')")

    # None of these code expressions should be detected as entropy secret candidates
    lines = [
        "API_KEY = os.environ.get('PROD_API_KEY')",
        "SECRET_KEY = re.compile(r'^[A-Za-z0-9_-]{24}$') ",
        "AUTH_TOKEN = get_access_token_now()",
        "DATABASE_PASSWORD = config.get('db_pass')",
    ]
    for line in lines:
        cands = detect_entropy_candidates(line, 1, "config.py", cfg)
        assert len(cands) == 0, f"Line unexpectedly flagged as entropy candidate: {line}"


def test_bug_5_doctor_baseline_findings_count(tmp_path):
    """Bug #5: doctor handles baseline files without 'set has no attribute findings_count'."""
    # Create git repo
    (tmp_path / ".git").mkdir()
    patterns = load_default_patterns()
    # Create a baseline file using create_baseline
    baseline_file = tmp_path / ".envguard-baseline.json"
    dummy_findings = scan_text("API_KEY = 'AKIAIOSFODNN7EXAMPLE'", "test.py", patterns)
    assert len(dummy_findings) > 0
    create_baseline(dummy_findings, baseline_file)

    report = run_diagnostics(tmp_path)
    baseline_check = next((c for c in report.checks if c.name == "Historical Baseline"), None)
    assert baseline_check is not None
    assert baseline_check.status == "PASS"
    assert "present (" in baseline_check.details
    assert "fingerprints)" in baseline_check.details


def test_bug_6_generic_high_entropy_secret_is_medium():
    """Bug #6: generic-high-entropy-secret must have MEDIUM severity, not HIGH."""
    cfg = AdvancedDetectionConfig(entropy_enabled=True, entropy_threshold=3.5, entropy_min_length=15)
    # High-entropy random credential value
    line = "SECRET_TOKEN = '9xK#mQ2!pZ1@4vL8wB7$dE3*yT6&'"
    cands = detect_entropy_candidates(line, 1, "auth.py", cfg)
    assert len(cands) == 1
    cand = cands[0]
    assert cand.rule_id == "generic-high-entropy-secret"
    assert cand.original_severity == "MEDIUM"

    scored = score_candidate(cand)
    assert scored.severity == "MEDIUM"

    patterns = load_default_patterns()
    findings = scan_lines([line], "auth.py", patterns, advanced_config=cfg)
    assert len(findings) == 1
    assert findings[0].rule_id == "generic-high-entropy-secret"
    assert findings[0].severity == "MEDIUM"


def test_bug_7_interactive_baseline_action(tmp_path, monkeypatch):
    """Bug #7: Option 6 Create/Update baseline in interactive mode executes without error."""
    # Setup a repo with a test secret
    (tmp_path / ".git").mkdir()
    (tmp_path / "secrets.py").write_text("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8")

    from envguard.interactive import run_baseline_action
    monkeypatch.setattr(Path, "cwd", lambda: tmp_path)

    # Calling run_baseline_action should succeed without TypeError
    run_baseline_action(tmp_path)

    baseline_file = tmp_path / ".envguard-baseline.json"
    assert baseline_file.is_file()
    data = json.loads(baseline_file.read_text(encoding="utf-8"))
    assert data["total_findings"] >= 1
