"""Unit tests for EnvGuard v0.2.5 Rich Terminal UI and styling system."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from rich.console import Console

from envguard.env_diff import EnvDiffResult
from envguard.interactive import display_menu_options, launch_interactive_menu
from envguard.reporter import (
    print_blocked_commit,
    print_check_passed,
    print_diff_report,
    print_hook_installed,
    print_scan_findings,
    print_status_dashboard,
)
from envguard.scanner import ScanFinding
from envguard.theme import (
    BADGE_HIGH,
    BADGE_LOW,
    BADGE_MEDIUM,
    create_error_panel,
    create_header_panel,
    create_project_context_table,
    create_success_panel,
    create_summary_panel,
    format_severity,
)


@pytest.fixture
def test_console():
    """Create a test console that records output to text buffer."""
    return Console(record=True, width=80)


def test_theme_format_severity():
    """Verify text severity labels are always present."""
    assert "HIGH" in format_severity("HIGH")
    assert "MEDIUM" in format_severity("MEDIUM")
    assert "LOW" in format_severity("LOW")
    assert "LOW" in format_severity("unknown")


def test_theme_panels_creation():
    """Verify reusable panel builders return valid renderables."""
    header = create_header_panel()
    assert header is not None

    success = create_success_panel("ALL CLEAR", "No problems found.")
    assert success is not None

    error = create_error_panel("Failed", "Bad input", "Try again", verbose_hint=True)
    assert error is not None

    summary = create_summary_panel(files_scanned=10, files_skipped=2, findings_count=1)
    assert summary is not None


def test_scan_findings_renders_table_with_masked_secrets(test_console):
    """Verify scan findings table includes severity labels and masks secrets."""
    finding = ScanFinding(
        rule_id="aws-access-key",
        rule_name="AWS Access Key ID",
        severity="HIGH",
        file_path="src/config.py",
        line_number=42,
        raw_value="AKIAIOSFODNN7EXAMPLE",
        masked_value="AKIA••••••••••••MPLE",
        fingerprint="sha256:abc123",
    )

    with patch("envguard.reporter.console", test_console):
        print_scan_findings([finding], stats={"files_scanned": 15, "files_skipped": 2})

    output = test_console.export_text()
    assert "HIGH" in output
    assert "aws-access-key" in output
    assert "src/config.py" in output
    assert "42" in output
    assert "AKIA••••••••••••MPLE" in output
    # Privacy check: raw secret MUST NOT appear in output
    assert "AKIAIOSFODNN7EXAMPLE" not in output
    assert "Files scanned:" in output


def test_scan_findings_clean_success(test_console):
    """Verify clean scan renders friendly success panel."""
    with patch("envguard.reporter.console", test_console):
        print_scan_findings([], stats={"files_scanned": 8, "files_skipped": 1})

    output = test_console.export_text()
    assert "SCAN PASSED" in output
    assert "No secrets were detected" in output


def test_blocked_commit_screen_renders_remediation(test_console):
    """Verify blocked commit alert includes guidance and blocking findings."""
    finding = ScanFinding(
        rule_id="stripe-secret-key",
        rule_name="Stripe Secret Key",
        severity="HIGH",
        file_path="payments.py",
        line_number=10,
        raw_value="sk_live_secret",
        masked_value="sk_live_••••••••",
        fingerprint="sha256:stripe123",
    )

    with patch("envguard.reporter.console", test_console):
        print_blocked_commit([finding])

    output = test_console.export_text()
    assert "ENVGUARD BLOCKED COMMIT" in output
    assert "HIGH" in output
    assert "Next Steps" in output
    assert "Remove sensitive credentials" in output
    assert "payments.py" in output
    assert "sk_live_secret" not in output


def test_check_passed_screens(test_console):
    """Verify check passed screens for both empty staged and clean staged files."""
    with patch("envguard.reporter.console", test_console):
        print_check_passed(no_staged=True)
    out1 = test_console.export_text()
    assert "CHECK PASSED" in out1
    assert "No staged Git changes" in out1

    test_console.clear()
    with patch("envguard.reporter.console", test_console):
        print_check_passed(low_findings_count=2, no_staged=False)
    out2 = test_console.export_text()
    assert "CHECK PASSED" in out2
    assert "2 low-severity warning(s)" in out2


def test_diff_report_rendering(test_console):
    """Verify environment drift report renders variable counts and missing keys."""
    drift_result = EnvDiffResult(
        missing_from_example=["DB_PASSWORD", "API_TOKEN"],
        extra_in_example=["DEPRECATED_VAR"],
        env_keys_count=10,
        example_keys_count=9,
    )

    with patch("envguard.reporter.console", test_console):
        print_diff_report(drift_result)

    output = test_console.export_text()
    assert "ENVIRONMENT CONFIGURATION DRIFT" in output
    assert "DB_PASSWORD" in output
    assert "API_TOKEN" in output
    assert "DEPRECATED_VAR" in output
    assert ".env variables: 10" in output


def test_status_dashboard_rendering(test_console):
    """Verify status dashboard displays all checks and overall status box."""
    with patch("envguard.reporter.console", test_console):
        status = print_status_dashboard(
            is_git=True,
            env_tracked=False,
            findings=[],
            diff_result=None,
            diff_error=None,
            hook_installed=True,
            config_status="VALID (.envguard.yml)",
            baseline_status="ACTIVE (5 entries)",
        )

    output = test_console.export_text()
    assert status == "SECURE"
    assert "ENVGUARD PROJECT STATUS" in output
    assert "Git Repository" in output
    assert "DETECTED" in output
    assert "Secrets" in output
    assert "CLEAN" in output
    assert "Configuration" in output
    assert "Baseline" in output
    assert "OVERALL STATUS: SECURE" in output


def test_hook_installed_feedback(test_console):
    """Verify hook installation explains preserved hooks and check command."""
    with patch("envguard.reporter.console", test_console):
        print_hook_installed("EnvGuard pre-commit hook was already installed and has been refreshed.")

    output = test_console.export_text()
    assert "Hook Refreshed" in output
    assert "envguard check" in output
    assert "Existing hooks were preserved" in output


def test_interactive_menu_options_display(test_console):
    """Verify interactive menu renders header and all 8 options."""
    with patch("envguard.interactive.console", test_console):
        display_menu_options(Path.cwd())

    output = test_console.export_text()
    assert "ENVGUARD" in output
    assert "Developer Security Safety Gate" in output
    assert "Project Security Status" in output
    assert "Scan Working Directory" in output
    assert "Check Staged Git Changes" in output
    assert "Compare .env vs .env.example" in output
    assert "Install Pre-Commit Hook" in output
    assert "Create / Update Baseline" in output
    assert "Exit" in output


def test_interactive_menu_baseline_option():
    """Verify option 6 triggers run_baseline_action."""
    with patch("builtins.input", side_effect=["6", "", "0"]):
        with patch("envguard.interactive.clear_screen"):
            with patch("envguard.interactive.run_baseline_action") as mock_baseline:
                with pytest.raises(SystemExit):
                    launch_interactive_menu()
                assert mock_baseline.called
