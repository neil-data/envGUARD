"""Tests for EnvGuard environment drift detection."""

import pytest

from envguard.env_diff import diff_env_keys, parse_env_text


def test_env_diff_specification_case():
    """Verify the exact sample scenario from specification:

    .env:
    DATABASE_URL=secret
    REDIS_URL=secret
    API_KEY=secret

    .env.example:
    DATABASE_URL=
    API_KEY=
    OLD_VARIABLE=

    Expected:
    Missing from .env.example: REDIS_URL
    Extra in .env.example: OLD_VARIABLE
    """
    env_content = """
    DATABASE_URL=postgres://user:pass@localhost:5432/db
    REDIS_URL=redis://localhost:6379/0
    API_KEY=super_secret_production_key_1234
    """

    example_content = """
    DATABASE_URL=
    API_KEY=
    OLD_VARIABLE=
    """

    env_keys = parse_env_text(env_content)
    example_keys = parse_env_text(example_content)

    result = diff_env_keys(env_keys, example_keys)

    assert result.has_drift is True
    assert result.missing_from_example == ["REDIS_URL"]
    assert result.extra_in_example == ["OLD_VARIABLE"]


def test_env_parser_supports_export_and_comments():
    sample = """
    # This is a comment
    export STRIPE_SECRET=sk_test_123
    export PORT=8080

    # Another comment section
    DEBUG=true
    """

    keys = parse_env_text(sample)
    assert keys == {"STRIPE_SECRET", "PORT", "DEBUG"}


def test_env_diff_synchronized():
    env_content = """
    PORT=3000
    DATABASE_URL=postgres://localhost
    JWT_SECRET=production_secret_key
    """

    example_content = """
    PORT=3000
    DATABASE_URL=postgres://example
    JWT_SECRET=changeme
    """

    env_keys = parse_env_text(env_content)
    example_keys = parse_env_text(example_content)

    result = diff_env_keys(env_keys, example_keys)
    assert result.has_drift is False
    assert len(result.missing_from_example) == 0
    assert len(result.extra_in_example) == 0
