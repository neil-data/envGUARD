"""Tests for interactive menu and safe demo simulation."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from envguard.interactive import (
    clear_screen,
    launch_interactive_menu,
    launch_separate_terminal,
    run_safe_demo_action,
)


def test_menu_exit_on_zero():
    """Verify selecting 0 calls sys.exit(0)."""
    with patch("builtins.input", side_effect=["0"]):
        with patch("envguard.interactive.clear_screen"):
            with pytest.raises(SystemExit) as exc_info:
                launch_interactive_menu()
            assert exc_info.value.code == 0


def test_menu_handles_invalid_input_then_exits():
    """Verify invalid input shows warning and continues loop until exit."""
    with patch("builtins.input", side_effect=["invalid_choice", "", "0"]):
        with patch("envguard.interactive.clear_screen"):
            with pytest.raises(SystemExit) as exc_info:
                launch_interactive_menu()
            assert exc_info.value.code == 0


def test_menu_actions_invoke_reusable_core_functions():
    """Verify each menu option executes its corresponding core function."""
    with patch("builtins.input", side_effect=["1", "", "2", "", "3", "", "4", "", "5", "", "0"]):
        with patch("envguard.interactive.clear_screen"):
            with patch("envguard.interactive.run_status_action") as mock_status:
                with patch("envguard.interactive.run_scan_action") as mock_scan:
                    with patch("envguard.interactive.run_check_action") as mock_check:
                        with patch("envguard.interactive.run_diff_action") as mock_diff:
                            with patch("envguard.interactive.run_install_hook_action") as mock_hook:
                                with pytest.raises(SystemExit):
                                    launch_interactive_menu()

                                assert mock_status.called
                                assert mock_scan.called
                                assert mock_check.called
                                assert mock_diff.called
                                assert mock_hook.called


def test_safe_demo_uses_temp_directory_and_cleans_up():
    """Verify that run_safe_demo_action creates an isolated temp repo and cleans up."""
    with patch("tempfile.TemporaryDirectory") as mock_temp_dir_cls:
        # Create a real temp directory context for the mock to execute with
        import tempfile
        real_temp = tempfile.TemporaryDirectory()
        mock_temp_dir_cls.return_value = real_temp

        run_safe_demo_action()

        # Check that after context exit, directory is cleaned up
        assert not Path(real_temp.name).exists()


def test_launch_separate_terminal_on_windows():
    """Verify Windows terminal launcher invokes wt.exe or cmd.exe via subprocess."""
    with patch("sys.platform", "win32"):
        with patch("shutil.which", return_value="C:\\Windows\\wt.exe"):
            with patch("subprocess.Popen") as mock_popen:
                launch_separate_terminal()
                assert mock_popen.called
                args = mock_popen.call_args[0][0]
                assert "C:\\Windows\\wt.exe" in args
                assert "EnvGuard Security Console" in args


def test_launch_separate_terminal_fallback_cmd():
    """Verify fallback to cmd.exe when wt.exe is absent on Windows."""
    with patch("sys.platform", "win32"):
        with patch("shutil.which", return_value=None):
            with patch("subprocess.Popen") as mock_popen:
                launch_separate_terminal()
                assert mock_popen.called
                args = mock_popen.call_args[0][0]
                assert "cmd.exe" in args[0]


def test_launch_separate_terminal_non_windows_fallback():
    """Verify non-Windows platforms fall back to current-terminal menu."""
    with patch("sys.platform", "linux"):
        with patch("envguard.interactive.launch_interactive_menu") as mock_menu:
            launch_separate_terminal()
            assert mock_menu.called
