"""Tests for GitHub Actions annotations and step summary integration."""

import io
from pathlib import Path
from envguard.ci import CIEnvironment
from envguard.github_actions import (
    generate_job_summary_markdown,
    write_github_annotations,
    write_github_job_summary,
)
from envguard.scanner import ScanFinding


def test_github_annotations_severity_mapping():
    """Verify HIGH -> error, MEDIUM -> warning, LOW -> notice annotations."""
    raw_secret = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    findings = [
        ScanFinding("gh-token", "GitHub Token", "HIGH", "src/auth.py", 12, raw_secret, "ghp_••••••••••••wxyz", "fp1"),
        ScanFinding("generic-key", "Generic Key", "MEDIUM", "app.py", 25, "secret2", "secr••••", "fp2"),
        ScanFinding("info-flag", "Info Flag", "LOW", "test.py", 5, "secret3", "secr••••", "fp3"),
    ]

    stream = io.StringIO()
    write_github_annotations(findings, stream=stream, force=True)
    output = stream.getvalue()

    assert "::error file=src/auth.py,line=12,title=EnvGuard HIGH::" in output
    assert "::warning file=app.py,line=25,title=EnvGuard MEDIUM::" in output
    assert "::notice file=test.py,line=5,title=EnvGuard LOW::" in output

    # Strict privacy check
    assert raw_secret not in output


def test_job_summary_markdown_generation():
    """Verify step summary markdown format and status."""
    findings = [
        ScanFinding("aws-key", "AWS Key", "HIGH", "config.py", 10, "AKIAIOSFODNN7EXAMPLE", "AKIA••••••••••••MPLE", "fp1"),
    ]
    ci_env = CIEnvironment(
        is_ci=True,
        provider="github",
        repository="owner/repo",
        branch="main",
        commit_sha="abcdef123456",
    )

    # Block on HIGH
    markdown = generate_job_summary_markdown(
        findings=findings,
        files_scanned=5,
        baseline_suppressed=2,
        block_on=["HIGH", "MEDIUM"],
        ci_env=ci_env,
    )

    assert "## EnvGuard Security Scan" in markdown
    assert "BLOCKED" in markdown
    assert "**Repository:** `owner/repo`" in markdown
    assert "AKIA••••••••••••MPLE" in markdown
    # Plaintext secret MUST NOT appear
    assert "AKIAIOSFODNN7EXAMPLE" not in markdown


def test_write_job_summary_to_file(tmp_path):
    """Verify write_github_job_summary writes to target summary file."""
    summary_file = tmp_path / "step_summary.md"
    findings = []
    success = write_github_job_summary(
        findings=findings,
        files_scanned=10,
        baseline_suppressed=0,
        block_on=["HIGH"],
        summary_file=summary_file,
        force=True,
    )
    assert success
    assert summary_file.is_file()
    content = summary_file.read_text(encoding="utf-8")
    assert "PASSED" in content
    assert "No active secrets detected" in content
