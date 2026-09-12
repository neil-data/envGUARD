"""Tests for EnvGuard secret scanner."""

from pathlib import Path
import tempfile
import pytest

from envguard.patterns import load_default_patterns
from envguard.scanner import scan_directory, scan_text
from envguard.utils import is_binary_bytes, is_placeholder, mask_secret


@pytest.fixture
def patterns():
    return load_default_patterns()


def test_detect_aws_access_key(patterns):
    # Fake AWS access key (20 chars starting with AKIA)
    sample = "aws_key = 'AKIAIOSFODNN7EXAMPLE'"
    findings = scan_text(sample, "config.py", patterns)

    assert len(findings) >= 1
    aws_findings = [f for f in findings if f.pattern_name == "AWS Access Key"]
    assert len(aws_findings) == 1
    assert aws_findings[0].confidence == "HIGH"
    assert aws_findings[0].file_path == "config.py"
    assert aws_findings[0].line_number == 1
    # Secret must be masked
    assert "AKIA" in aws_findings[0].masked_value
    assert "MPLE" in aws_findings[0].masked_value
    assert "••••" in aws_findings[0].masked_value
    assert aws_findings[0].raw_value not in aws_findings[0].masked_value


def test_detect_github_token(patterns):
    # Fake GitHub Personal Access Token (classic ghp_)
    fake_token = "ghp_0123456789abcdefghijklmnopqrstuv"
    sample = f"GITHUB_TOKEN = '{fake_token}'"
    findings = scan_text(sample, "deploy.sh", patterns)

    gh_findings = [f for f in findings if f.pattern_name == "GitHub Personal Access Token"]
    assert len(gh_findings) == 1
    assert gh_findings[0].confidence == "HIGH"
    assert "••••" in gh_findings[0].masked_value
    assert fake_token not in gh_findings[0].masked_value


def test_detect_stripe_key(patterns):
    # Fake Stripe Secret Key
    fake_stripe = "".join(["sk_", "test_", "abcdefghijklmnopqrstuvwxyz012345"])
    sample = f"stripe_secret = \"{fake_stripe}\""
    findings = scan_text(sample, "payments.py", patterns)

    stripe_findings = [f for f in findings if f.pattern_name == "Stripe Secret Key"]
    assert len(stripe_findings) == 1
    assert stripe_findings[0].confidence == "HIGH"
    assert fake_stripe not in stripe_findings[0].masked_value


def test_detect_pem_private_key(patterns):
    sample = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y3...\n"
        "-----END RSA PRIVATE KEY-----"
    )
    findings = scan_text(sample, "server.key", patterns)
    pk_findings = [f for f in findings if f.pattern_name == "Private Key"]
    assert len(pk_findings) == 1
    assert pk_findings[0].confidence == "HIGH"
    assert "[MASKED]" in pk_findings[0].masked_value


def test_ignore_placeholder_values(patterns):
    placeholders = [
        "API_KEY=your_api_key",
        "API_KEY=your-api-key",
        "API_KEY=changeme",
        "API_KEY=change_me",
        "API_KEY=example",
        "API_KEY=placeholder",
        "API_KEY=your_secret",
        "API_KEY=<your-key>",
        "API_KEY=<api-key>",
        "API_KEY=YOUR_API_KEY",
        "API_KEY=xxxxxxxxxxxxxxxx",
        "API_KEY=0000000000000000",
    ]
    for sample in placeholders:
        findings = scan_text(sample, "test.env", patterns)
        assert len(findings) == 0, f"Expected '{sample}' to be ignored as a placeholder, but found: {findings}"


def test_ignore_empty_api_key(patterns):
    empty_samples = [
        "API_KEY=",
        "API_KEY=\"\"",
        "API_KEY=''",
        "SECRET=",
        "PASSWORD=",
    ]
    for sample in empty_samples:
        findings = scan_text(sample, ".env.example", patterns)
        assert len(findings) == 0, f"Expected '{sample}' to be ignored, but found: {findings}"


def test_scan_directory_skips_binary_files(patterns, tmp_path):
    # Create text file with a secret
    txt_file = tmp_path / "secret.txt"
    txt_file.write_text("API_KEY=real_production_secret_key_12345", encoding="utf-8")

    # Create binary file containing null bytes
    bin_file = tmp_path / "data.bin"
    bin_file.write_bytes(b"AKIAIOSFODNN7EXAMPLE\x00\x01\x02\x03\xff")

    findings = scan_directory(tmp_path, patterns=patterns, respect_gitignore=False)
    scanned_files = {f.file_path for f in findings}

    assert "secret.txt" in scanned_files
    assert "data.bin" not in scanned_files
