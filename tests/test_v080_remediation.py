"""Comprehensive tests for EnvGuard v0.8.0 Remediation and Secrets Manager Integration."""

import json
import os
from pathlib import Path
import subprocess
import pytest
from click.testing import CliRunner

from envguard.cli import main
from envguard.remediation import (
    apply_remediation_plan,
    check_git_cleanliness,
    create_remediation_plan,
    inspect_python_assignment,
)
from envguard.scanner import ScanFinding
from envguard.secrets_manager import detect_secrets_manager_reference


def test_secrets_manager_recognition():
    """Verify local detection of common secrets manager references without network calls."""
    # AWS Secrets Manager
    assert detect_secrets_manager_reference("client = boto3.client('secretsmanager')") is not None
    assert detect_secrets_manager_reference("resp = client.get_secret_value(SecretId='my-secret')") is not None

    # HashiCorp Vault
    assert detect_secrets_manager_reference("client = hvac.Client(url=os.environ['VAULT_ADDR'])") is not None
    assert detect_secrets_manager_reference("secret = client.secrets.kv.v2.read_secret_version(path='db')") is not None

    # Azure Key Vault
    assert detect_secrets_manager_reference("from azure.keyvault.secrets import SecretClient") is not None
    assert detect_secrets_manager_reference("secret = client.get_secret('my-secret')") is not None

    # GCP Secret Manager
    assert detect_secrets_manager_reference("from google.cloud import secretmanager") is not None
    assert detect_secrets_manager_reference("client = secretmanager.SecretManagerServiceClient()") is not None

    # Environment Lookup
    assert detect_secrets_manager_reference("key = os.environ.get('API_KEY')") is not None
    assert detect_secrets_manager_reference("key = os.getenv('API_KEY')") is not None

    # Raw secret assignment (not secrets manager)
    assert detect_secrets_manager_reference("API_KEY = 'AKIA1234567890EXAMPLE'") is None


def test_python_assignment_inspection_safe(tmp_path):
    """Simple single-line string assignment is safely recognized."""
    py_file = tmp_path / "app.py"
    py_file.write_text("API_KEY = \"secret123\"\n", encoding="utf-8")

    is_safe, var_name, skip_reason, needs_import = inspect_python_assignment(
        file_path=py_file,
        line_number=1,
        raw_secret="secret123",
    )
    assert is_safe is True
    assert var_name == "API_KEY"
    assert skip_reason is None
    assert needs_import is True


def test_python_assignment_inspection_unsafe(tmp_path):
    """Unsafe/ambiguous expressions (f-strings, dicts, multiline) are marked manual."""
    # Dictionary value
    py_file = tmp_path / "app.py"
    py_file.write_text("CONFIG = {'key': 'secret123'}\n", encoding="utf-8")

    is_safe, var_name, skip_reason, _ = inspect_python_assignment(
        file_path=py_file,
        line_number=1,
        raw_secret="secret123",
    )
    assert is_safe is False
    assert "manual remediation required" in skip_reason.lower()

    # Function call
    py_file.write_text("KEY = compute_key('secret123')\n", encoding="utf-8")
    is_safe2, _, skip_reason2, _ = inspect_python_assignment(
        file_path=py_file,
        line_number=1,
        raw_secret="secret123",
    )
    assert is_safe2 is False
    assert "manual remediation required" in skip_reason2.lower()


def test_remediation_dry_run_default(tmp_path):
    """By default, 'envguard fix' operates in dry-run mode and does NOT modify files."""
    py_file = tmp_path / "app.py"
    original_code = "GITHUB_TOKEN = \"ghp_1234567890abcdefghijklmnopqrstuvwxyz\"\n"
    py_file.write_text(original_code, encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["fix", str(tmp_path)])
    assert result.exit_code == 0
    assert "DRY-RUN MODE" in result.output
    assert "Proposed Transformations" in result.output
    assert "Credential Rotation Required" in result.output

    # File MUST remain completely untouched
    assert py_file.read_text(encoding="utf-8") == original_code
    assert not (tmp_path / ".env").exists()
    assert not (tmp_path / ".env.example").exists()


def test_remediation_apply_execution_and_import_os(tmp_path):
    """Running 'envguard fix --apply --allow-dirty' rewrites assignment and injects 'import os'."""
    py_file = tmp_path / "app.py"
    secret_val = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    py_file.write_text(f"GITHUB_TOKEN = \"{secret_val}\"\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["fix", str(tmp_path), "--apply", "--allow-dirty"])
    assert result.exit_code == 0
    assert "CHANGES APPLIED SUCCESSFULLY" in result.output
    assert "Credential Rotation Required" in result.output

    new_content = py_file.read_text(encoding="utf-8")
    assert "import os" in new_content
    assert "GITHUB_TOKEN = os.environ.get(\"GITHUB_TOKEN\")" in new_content
    assert secret_val not in new_content

    # .env should have the secret
    env_file = tmp_path / ".env"
    assert env_file.is_file()
    assert f'GITHUB_TOKEN="{secret_val}"' in env_file.read_text(encoding="utf-8")

    # .env.example should strictly have placeholder ONLY (NEVER the secret)
    example_file = tmp_path / ".env.example"
    assert example_file.is_file()
    example_content = example_file.read_text(encoding="utf-8")
    assert secret_val not in example_content
    assert 'GITHUB_TOKEN="your-secret-key-here"' in example_content


def test_remediation_preserves_existing_import_os(tmp_path):
    """If 'import os' already exists, it is not duplicated."""
    py_file = tmp_path / "app.py"
    secret_val = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    py_file.write_text(f"import os\n\nTOKEN = \"{secret_val}\"\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["fix", str(tmp_path), "--apply", "--allow-dirty"])
    assert result.exit_code == 0

    new_content = py_file.read_text(encoding="utf-8")
    # Must only contain one 'import os'
    assert new_content.count("import os") == 1
    assert "TOKEN = os.environ.get(\"TOKEN\")" in new_content


def test_git_cleanliness_requirement(tmp_path):
    """By default, --apply fails if Git working tree is dirty unless --allow-dirty is passed."""
    subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(tmp_path), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(tmp_path), capture_output=True, check=True)

    # Create uncommitted tracked or untracked file to make repo dirty
    py_file = tmp_path / "app.py"
    py_file.write_text("KEY = \"ghp_1234567890abcdefghijklmnopqrstuvwxyz\"\n", encoding="utf-8")

    runner = CliRunner()
    # Without --allow-dirty -> fails
    result1 = runner.invoke(main, ["fix", str(tmp_path), "--apply"])
    assert result1.exit_code == 2
    assert "uncommitted or unstaged changes" in result1.output

    # With --allow-dirty -> succeeds
    result2 = runner.invoke(main, ["fix", str(tmp_path), "--apply", "--allow-dirty"])
    assert result2.exit_code == 0


def test_remediation_json_output(tmp_path):
    """'envguard fix --format json' outputs valid, versioned JSON data with zero plaintext leaks in example/status."""
    py_file = tmp_path / "app.py"
    secret_val = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    py_file.write_text(f"TOKEN = \"{secret_val}\"\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["fix", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["command"] == "fix"
    assert data["applied"] is False
    assert len(data["safe_actions"]) == 1
    assert data["safe_actions"][0]["env_var_name"] == "TOKEN"
    assert secret_val not in str(data["safe_actions"][0]["masked_secret"])
    assert "TOKEN" in data["example_keys_added"]


def test_remediation_skips_secrets_manager_patterns(tmp_path):
    """Findings that reside on lines referencing secrets managers are skipped from code rewrite."""
    py_file = tmp_path / "app.py"
    # Even if finding regex triggers, secrets manager context prevents blind rewrite
    dummy_key = "".join(["sk_", "live_", "1234567890abcdef12345678"])
    py_file.write_text(f"secret = client.get_secret('{dummy_key}')\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["fix", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["summary"]["skipped_secrets_manager_count"] >= 1
    assert any("Azure Key Vault" in sm["manager"] for sm in data["secrets_manager_references"])
