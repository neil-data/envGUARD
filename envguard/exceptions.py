from typing import Optional


class EnvGuardError(Exception):
    """Base exception for all EnvGuard errors."""
    pass


class ConfigurationError(EnvGuardError):
    """Raised when configuration file parsing or validation fails."""

    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        expected: Optional[str] = None,
        received: Optional[str] = None,
        config_path: Optional[str] = None,
        example: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.field = field
        self.expected = expected
        self.received = received
        self.config_path = config_path
        self.example = example


class GitError(EnvGuardError):
    """Raised when a Git command or repository inspection fails."""
    pass


class ScanError(EnvGuardError):
    """Raised when an unrecoverable scanning error occurs."""
    pass


class EnvDiffError(EnvGuardError):
    """Raised when environment drift comparison fails."""
    pass


class HookError(EnvGuardError):
    """Raised when pre-commit hook installation or management fails."""
    pass


class BaselineError(EnvGuardError):
    """Raised when baseline creation, reading, or validation fails."""
    pass
