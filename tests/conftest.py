import pytest
from envguard.patterns import load_default_patterns


@pytest.fixture
def patterns():
    return load_default_patterns()
