"""Tests for pattern matching and secret masking."""

import pytest

from envguard.patterns import load_default_patterns
from envguard.utils import mask_secret


def test_load_default_patterns():
    patterns = load_default_patterns()
    assert len(patterns) >= 7

    names = [p.name for p in patterns]
    assert "AWS Access Key" in names
    assert "GitHub Personal Access Token" in names
    assert "Stripe Secret Key" in names
    assert "Private Key" in names

    ids = [p.id for p in patterns]
    assert "aws-access-key" in ids
    assert "github-token" in ids
    assert "stripe-secret-key" in ids
    assert "pem-private-key" in ids

    for p in patterns:
        assert p.id
        assert p.severity in ("HIGH", "MEDIUM", "LOW")


def test_mask_secret_never_reveals_full_secret():
    # Long secret (e.g. AWS access key)
    aws_secret = "AKIA1234567890ABCDEFG"
    masked_aws = mask_secret(aws_secret)
    assert aws_secret not in masked_aws
    assert masked_aws == "AKIA••••••••••••DEFG"

    # Medium secret (8-15 characters)
    medium_secret = "abcd1234"
    masked_med = mask_secret(medium_secret)
    assert medium_secret not in masked_med
    assert masked_med == "ab••••34"

    # Short secret
    short_secret = "secret"
    masked_short = mask_secret(short_secret)
    assert short_secret not in masked_short
    assert masked_short == "s••••t"


def test_mask_secret_private_key():
    pem = "-----BEGIN RSA PRIVATE KEY-----"
    masked = mask_secret(pem)
    assert masked == "-----BEGIN RSA PRIVATE KEY----- [MASKED]"

    ec_pem = "-----BEGIN EC PRIVATE KEY-----"
    assert mask_secret(ec_pem) == "-----BEGIN EC PRIVATE KEY----- [MASKED]"


def test_mask_secret_empty_or_edge_cases():
    assert mask_secret("") == "[EMPTY]"
    assert mask_secret("a") == "••••"
    assert mask_secret("ab") == "••••"
