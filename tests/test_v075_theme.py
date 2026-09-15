"""Tests for EnvGuard v0.7.5 Centralized Theme System."""

from pathlib import Path
import pytest
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from envguard.ui.theme import (
    BADGE_BLOCKED,
    BADGE_CLEAN,
    BADGE_CRITICAL,
    BADGE_ERROR,
    BADGE_HIGH,
    BADGE_LOW,
    BADGE_MEDIUM,
    BADGE_PASS,
    BADGE_WARNING,
    COLOR_HIGH,
    COLOR_LOW,
    COLOR_MASKED,
    COLOR_MEDIUM,
    SEVERITY_STYLES,
    STATUS_STYLES,
    create_error_panel,
    create_header_panel,
    create_panel,
    create_project_context_table,
    create_standard_table,
    create_success_panel,
    create_summary_panel,
    create_warning_panel,
    format_severity,
    format_status,
    render_finding_snippet,
)
from envguard.scanner import ScanFinding


def test_theme_severity_badges_and_tokens():
    """Verify severity badges contain explicit text labels and styles."""
    assert "HIGH" in BADGE_HIGH
    assert "bold red" in BADGE_HIGH
    assert "MEDIUM" in BADGE_MEDIUM
    assert "bold yellow" in BADGE_MEDIUM
    assert "LOW" in BADGE_LOW
    assert "bold blue" in BADGE_LOW

    assert format_severity("high") == BADGE_HIGH
    assert format_severity("MEDIUM") == BADGE_MEDIUM
    assert format_severity("low") == BADGE_LOW
    assert format_severity("unknown") == BADGE_LOW


def test_theme_status_badges_and_tokens():
    """Verify status badges and format_status mappings."""
    assert "PASS" in BADGE_PASS
    assert "WARNING" in BADGE_WARNING
    assert "ERROR" in BADGE_ERROR
    assert "BLOCKED" in BADGE_BLOCKED
    assert "CLEAN" in BADGE_CLEAN
    assert "CRITICAL" in BADGE_CRITICAL

    assert format_status("pass") == BADGE_PASS
    assert format_status("WARNING") == BADGE_WARNING
    assert format_status("error") == BADGE_ERROR
    assert format_status("blocked") == BADGE_BLOCKED
    assert format_status("clean") == BADGE_CLEAN
    assert format_status("critical") == BADGE_CRITICAL


def test_theme_reusable_panel_builders():
    """Verify reusable panel builders construct valid Rich Panels."""
    p = create_panel("Hello World", title="Test Title", border_style="green")
    assert isinstance(p, Panel)
    assert p.border_style == "green"

    hdr = create_header_panel()
    assert isinstance(hdr, Panel)

    succ = create_success_panel("Success Title", "Operation completed.")
    assert isinstance(succ, Panel)
    assert succ.border_style == "green"

    err = create_error_panel("Error Title", "Something failed.", suggestion="Try again.")
    assert isinstance(err, Panel)
    assert err.border_style == "red"

    warn = create_warning_panel("Warning Title", "Careful.", suggestion="Take action.")
    assert isinstance(warn, Panel)
    assert warn.border_style == "yellow"

    summ = create_summary_panel(files_scanned=10, files_skipped=2, findings_count=0)
    assert isinstance(summ, Panel)
    assert summ.border_style == "green"

    summ_err = create_summary_panel(files_scanned=10, files_skipped=2, findings_count=3)
    assert isinstance(summ_err, Panel)
    assert summ_err.border_style == "red"


def test_theme_standard_table_builder():
    """Verify create_standard_table builds unified tables."""
    cols = [
        {"name": "Col1", "style": "bold"},
        {"name": "Col2", "justify": "right"},
    ]
    tbl = create_standard_table(title="Standard Table", columns=cols)
    assert isinstance(tbl, Table)
    assert len(tbl.columns) == 2


def test_syntax_security_pre_masking():
    """CRITICAL SECURITY TEST: Ensure raw plaintext secrets NEVER reach rich.syntax.Syntax."""
    raw_secret = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    masked = "ghp_••••••••••••••••••••••••••••••••••••"
    line_snippet = f"GITHUB_TOKEN = \"{raw_secret}\""

    syntax_obj = render_finding_snippet(
        raw_snippet=line_snippet,
        raw_value=raw_secret,
        masked_value=masked,
        file_path="config.py",
        line_number=14,
    )
    assert syntax_obj is not None
    assert isinstance(syntax_obj, Syntax)

    # 1. Plaintext secret MUST NOT be present in syntax code buffer
    assert raw_secret not in syntax_obj.code
    # 2. Masked secret MUST be present in syntax code buffer
    assert masked in syntax_obj.code
    # 3. Lexer should match Python for .py file
    assert syntax_obj.lexer.name.lower() == "python"

    # Render through console to verify rendered stream is safe
    console = Console(record=True, width=120)
    console.print(syntax_obj)
    rendered = console.export_text()

    assert raw_secret not in rendered
    assert masked in rendered
