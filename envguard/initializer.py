"""Project initializer for EnvGuard v0.7.0.
Creates initial .envguard.yml and .envguardignore.
"""

from dataclasses import dataclass
from pathlib import Path

version = "0.7.0"


default_envguard_yml = """# EnvGuard Configuration
version: 1

scan:
  max_file_size_mb: 5.0
  block_on:
    - HIGH
    - MEDIUM
  respect_gitignore: true

exclude: []

rules:
  disabled: []
  severity_overrides: {}

reporting:
  color: true
  show_fingerprints: false

ci:
  changed_files_only: true
  base_branch: null
  annotations: true
  job_summary: true
"""

default_envguardignore = """# .envguardignore
# Files and paths excluded from EnvGuard secret scanning

# Test data and fixtures
tests/test_data/
spec/fixtures/

# Documentation examples
mocks/
examples/

# Temporary files
logs/
*.log
"""


@dataclass
class InitResult:
    config_created: bool = False
    ignore_created: bool = False
    config_existed: bool = False
    ignore_existed: bool = False
    config_path: str = ""
    ignore_path: str = ""


def init_project(repo_path: Path) -> InitResult:
    """Initialize EnvGuard config and ignore files safely without overwriting."""
    result = InitResult()
    config_f = repo_path / ".envguard.yml"
    ignore_f = repo_path / ".envguardignore"

    result.config_path = str(config_f)
    result.ignore_path = str(ignore_f)

    if config_f.is_file():
        result.config_existed = True
    else:
        config_f.write_text(default_envguard_yml.lstrip(), encoding="utf-8")
        result.config_created = True

    if ignore_f.is_file():
        result.ignore_existed = True
    else:
        ignore_f.write_text(default_envguardignore.lstrip(), encoding="utf-8")
        result.ignore_created = True

    return result
