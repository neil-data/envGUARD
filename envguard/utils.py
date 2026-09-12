"""Utility functions for EnvGuard: secret masking, binary detection, and placeholder whitelisting."""

from pathlib import Path
import re
from typing import Union

# Whitelist of placeholder strings that often appear in examples, configs, or templates
PLACEHOLDER_WORDS = {
    "your_api_key",
    "your-api-key",
    "yourapikey",
    "your_secret",
    "your-secret",
    "yoursecret",
    "your_password",
    "your-password",
    "yourpassword",
    "changeme",
    "change_me",
    "change-me",
    "example",
    "placeholder",
    "sample",
    "test",
    "testing",
    "fake",
    "dummy",
    "mock",
    "default",
    "secret",
    "password",
    "apikey",
    "api_key",
    "token",
    "mysecretkey",
    "my_secret_key",
    "none",
    "null",
    "undefined",
    "true",
    "false",
}


def add_custom_placeholders(custom: set) -> None:
    """Add user-defined placeholders to the active whitelist."""
    global PLACEHOLDER_WORDS
    PLACEHOLDER_WORDS.update(p.strip().lower() for p in custom if p.strip())



def mask_secret(value: str) -> str:
    """Mask a sensitive value so the full secret is never printed in logs or terminal output.

    Rules:
    - PEM Private Keys: Returns '-----BEGIN <TYPE> PRIVATE KEY----- [MASKED]'
    - Long strings (>= 16 chars): AKIA1234567890ABCDEFG -> AKIA••••••••••••CDEFG
    - Medium strings (8-15 chars): abcd1234 -> ab••••34
    - Short strings (3-7 chars): secret -> s••••t
    - Very short (<= 2 chars): ••••
    """
    if not value:
        return "[EMPTY]"

    cleaned = value.strip().strip("'\"")

    # Handle PEM / OpenSSH private key headers
    if "-----BEGIN" in cleaned:
        pem_match = re.search(r"(-----BEGIN [A-Z0-9_\- ]+-----)", cleaned)
        if pem_match:
            return f"{pem_match.group(1)} [MASKED]"
        return "-----BEGIN " + "PRIVATE KEY----- [MASKED]"

    length = len(cleaned)
    if length <= 2:
        return "••••"
    if length < 8:
        return f"{cleaned[0]}••••{cleaned[-1]}"
    if length < 16:
        return f"{cleaned[:2]}••••{cleaned[-2:]}"

    # For >= 16 chars: show first 4 and last 4, mask middle with fixed-length bullet line
    return f"{cleaned[:4]}••••••••••••{cleaned[-4:]}"


def is_placeholder(value: str) -> bool:
    """Check if a detected value is an obvious placeholder or dummy value.

    Case-insensitive matching against known templates, angle brackets,
    and repeated dummy sequences.
    """
    if not value:
        return True

    val = value.strip().strip("'\"")
    if not val:
        return True

    lower = val.lower()

    # Exact match with common placeholder names
    if lower in PLACEHOLDER_WORDS:
        return True

    # Bracket-enclosed placeholders like <your-key>, [api-key], ${API_KEY}
    if (
        (lower.startswith("<") and lower.endswith(">"))
        or (lower.startswith("[") and lower.endswith("]"))
        or (lower.startswith("{") and lower.endswith("}"))
        or (lower.startswith("${") and lower.endswith("}"))
    ):
        return True

    # Check if string contains obvious placeholder prefixes
    if any(
        lower.startswith(prefix)
        for prefix in ("your_", "your-", "enter_", "enter-", "sample_", "test_")
    ):
        return True

    # Check for all repeating single characters (e.g. 'xxxxxxxxx', '00000000')
    if len(set(lower)) <= 1:
        return True

    # Check for simple sequence dummy keys
    if lower in ("12345678", "123456789", "1234567890", "abcdefgh", "abcdef123456"):
        return True

    return False


def is_binary_bytes(content: bytes) -> bool:
    """Heuristic to detect binary content by checking for null bytes in the first 8KB."""
    if not content:
        return False
    sample = content[:8192]
    return b"\x00" in sample


def is_binary_file(filepath: Union[str, Path]) -> bool:
    """Check if a file is binary by reading its initial chunk."""
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(8192)
            return is_binary_bytes(chunk)
    except Exception:
        # If file cannot be read, treat safely as non-processable binary
        return True
