"""Custom exception hierarchy for EnvGuard."""


class EnvGuardError(Exception):
    """Base exception for all EnvGuard errors."""
    pass


class ConfigurationError(EnvGuardError):
    """Raised when configuration file parsing or validation fails."""
    pass


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
