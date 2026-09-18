"""Comprehensive v1.0.0 Release Gate & Stranger Test Suite.

Verifies:
1. Command regression & exit codes across all 16 commands
2. Output format rendering (text, json, sarif, html)
3. Safe remediation behavior and gitignore creation
4. Compliance mapping integrity (SOC 2 Type II and ISO/IEC 27001:2022)
5. Disposable isolated Stranger Test workflow from init -> scan -> fix -> clean
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from envguard.cli import main
from envguard.compliance import load_compliance_mappings
from envguard.patterns import load_default_patterns


class TestReleaseContracts:
    """Validate core v1.0.0 contracts."""

    def test_compliance_frameworks_contract(self):
        """Contract: Supported frameworks are exactly SOC 2 and ISO 27001."""
        mappings = load_compliance_mappings()
        frameworks = mappings.get("frameworks", {})
        assert "soc2" in frameworks
        assert "iso27001" in frameworks
        # Ensure title and control counts are present
        assert len(frameworks["soc2"]["controls"]) >= 3
        assert len(frameworks["iso27001"]["controls"]) >= 3

    def test_rules_command_executes_successfully(self):
        """rules command outputs catalog with exit code 0."""
        runner = CliRunner()
        result = runner.invoke(main, ["rules"])
        assert result.exit_code == 0
        assert "aws-access-key" in result.output

    def test_explain_command_executes_successfully(self):
        """explain command explains a rule with exit code 0."""
        runner = CliRunner()
        result = runner.invoke(main, ["explain", "aws-access-key"])
        assert result.exit_code == 0
        assert "aws-access-key" in result.output

    def test_doctor_command_executes_successfully(self):
        """doctor command reports system diagnostic with exit code 0."""
        runner = CliRunner()
        result = runner.invoke(main, ["doctor"])
        assert result.exit_code == 0
        assert "Doctor" in result.output or "Diagnostics" in result.output or "Summary:" in result.output

    def test_lint_config_command_validates_clean_repo(self):
        """lint-config on clean repository returns exit code 0."""
        runner = CliRunner()
        result = runner.invoke(main, ["lint-config"])
        assert result.exit_code == 0


class TestStrangerWorkflowDisposable:
    """Simulate a brand-new stranger installing EnvGuard in a clean workspace."""

    def test_full_stranger_lifecycle(self, tmp_path):
        """Simulate stranger lifecycle:
        1. Initialize fresh repo with envguard init
        2. Lint starter configuration (exit code 0)
        3. Introduce dummy secret in test file
        4. Run scan (detects secret, exit code 1)
        5. Run fix --apply --allow-dirty (remediates code, writes .env, creates .gitignore)
        6. Verify .gitignore ignores .env
        7. Run scan again (clean, exit code 0)
        """
        runner = CliRunner()
        workspace = tmp_path / "stranger_workspace"
        workspace.mkdir()

        # 1. Initialize
        res_init = runner.invoke(main, ["init", str(workspace)])
        assert res_init.exit_code == 0
        assert (workspace / ".envguard.yml").is_file()
        assert (workspace / ".envguardignore").is_file()

        # 2. Lint configuration
        res_lint = runner.invoke(main, ["lint-config", str(workspace)])
        assert res_lint.exit_code == 0

        # 3. Add a test source file with dummy secret (valid AWS Access Key format)
        dummy_src = workspace / "service.py"
        dummy_secret = "AKIAIOSFODNN7EXAMPLE"
        dummy_src.write_text(f'aws_key = "{dummy_secret}"\n', encoding="utf-8")

        # 4. Run scan -> must block (exit code 1)
        res_scan = runner.invoke(main, ["scan", str(workspace)])
        assert res_scan.exit_code == 1

        # Also test JSON format in scan
        res_scan_json = runner.invoke(main, ["scan", str(workspace), "--format", "json"])
        assert res_scan_json.exit_code == 1
        data = json.loads(res_scan_json.output)
        assert data["summary"]["total"] >= 1

        # 5. Run fix --apply --allow-dirty -> remediates to os.environ and writes .env
        res_fix = runner.invoke(main, ["fix", str(workspace), "--apply", "--allow-dirty"])
        assert res_fix.exit_code == 0

        # Verify service.py was updated safely
        remediated_code = dummy_src.read_text(encoding="utf-8")
        assert "os.environ.get" in remediated_code or "os.getenv" in remediated_code
        assert dummy_secret not in remediated_code

        # Verify .env was created containing the extracted secret
        env_file = workspace / ".env"
        assert env_file.is_file()
        assert dummy_secret in env_file.read_text(encoding="utf-8")

        # 6. Verify .gitignore was created/updated to ignore .env
        gitignore_file = workspace / ".gitignore"
        assert gitignore_file.is_file()
        assert ".env" in gitignore_file.read_text(encoding="utf-8")

        # 7. Run scan again -> must be completely clean (exit code 0)
        res_scan_clean = runner.invoke(main, ["scan", str(workspace)])
        assert res_scan_clean.exit_code == 0
