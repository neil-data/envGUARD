"""Unit tests for EnvGuard v0.9.11 - Generic High-Entropy Detection Redesign."""

import pytest
from pathlib import Path

from envguard.config import EnvGuardConfig
from envguard.detectors.entropy_detector import (
    detect_entropy_candidates,
    is_mime_type,
    is_package_or_plugin,
    is_domain_or_url,
    is_mock_or_test_placeholder,
    is_deterministic_hash_or_fingerprint,
    is_code_identifier_or_constant,
    is_css_declaration_string,
    _is_unquoted_code_syntax_or_literal,
)
from envguard.detectors.context_detector import analyze_context, is_line_credential_context
from envguard.detectors.scoring import score_candidate
from envguard.patterns import load_default_patterns
from envguard.scanner import scan_text


def test_detects_genuine_credentials():
    """True secrets with high entropy and credential variable or context must be detected."""
    # Variable assignment with custom credential identifier and high entropy
    content = "user_cred = 'xK9#m$L2!vP9@wQ4zR7^tY1&aBcdE99'\n"
    cfg = EnvGuardConfig()
    cands = detect_entropy_candidates(content, 1, "config.py", cfg.advanced_detection)
    assert len(cands) >= 1
    assert cands[0].rule_id == "generic-high-entropy-secret"

    # Password assignment with symbol diversity
    content_pass = 'db_pass = "xK9#m$L2!vP9@wQ4zR7^tY1&aBcdE99"\n'
    cands_pass = detect_entropy_candidates(content_pass, 1, "db.py", cfg.advanced_detection)
    assert len(cands_pass) >= 1
    assert "symbol_diversity_randomness" in cands_pass[0].signals

    # Context credential call (e.g., auth function parameter)
    content_auth = 'verify_custom_token("xK9#m$L2!vP9@wQ4zR7^tY1&aBcdE99")\n'
    cands_auth = detect_entropy_candidates(content_auth, 1, "auth.py", cfg.advanced_detection)
    assert len(cands_auth) >= 1
    assert "credential_context" in cands_auth[0].signals


def test_analyze_context():
    """Analyze context should properly distinguish credentials vs non-secret keywords."""
    res_cred = analyze_context("client_secret")
    assert res_cred.is_credential_context is True

    res_non = analyze_context("tle_age")
    assert res_non.is_non_secret_context is True

    res_sess = analyze_context("session_id")
    assert res_sess.is_non_secret_context is True


def test_rejects_unquoted_code_syntax_and_literals():
    """Unquoted code syntax, numbers, booleans, and function calls must not be flagged."""
    assert _is_unquoted_code_syntax_or_literal("useRef<HTMLDivElement>(null)")
    assert _is_unquoted_code_syntax_or_literal("true")
    assert _is_unquoted_code_syntax_or_literal("false")
    assert _is_unquoted_code_syntax_or_literal("180")
    assert _is_unquoted_code_syntax_or_literal("1.5")
    assert _is_unquoted_code_syntax_or_literal("EvasionClass.ENVIRONMENT_CHECK")
    assert _is_unquoted_code_syntax_or_literal("null;")
    assert _is_unquoted_code_syntax_or_literal("controls.enableDamping = true")


def test_rejects_structural_non_secrets():
    """MIME types, package names, CSS strings, domains, and mock placeholders must not be flagged."""
    assert is_mime_type("application/vnd.google-apps.folder")
    assert is_mime_type("image/svg+xml")

    assert is_package_or_plugin("@vitejs/plugin-react")
    assert is_package_or_plugin("@types/three")

    assert is_domain_or_url("https://registry.npmjs.org/three")
    assert is_domain_or_url("satellites.orbit-recovery.test")

    assert is_mock_or_test_placeholder('b"MOCK_FRAME_DATA_12345"')
    assert is_mock_or_test_placeholder('your_token')
    assert is_mock_or_test_placeholder('your_api_key_here')

    assert is_deterministic_hash_or_fingerprint("sha256:4a5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c")
    assert is_deterministic_hash_or_fingerprint("123e4567-e89b-12d3-a456-426614174000")

    assert is_code_identifier_or_constant("CreateProcessW")
    assert is_code_identifier_or_constant("AccessibilityPerformAction")
    assert is_code_identifier_or_constant("requests_sms_and_overlay_together")
    assert is_code_identifier_or_constant("RA_OF_ASC_NODE")

    assert is_css_declaration_string("border-box; margin: 0; padding: 0", "box-sizing: border-box; margin: 0; padding: 0")


def test_scanner_ignores_report_artifacts_and_css():
    """Scanning realistic non-secret files produces zero generic-high-entropy-secret false positives."""
    sample_code = """
    import { useRef, useEffect } from 'react';
    import reactLogo from './assets/react.svg';
    import viteLogo from '/vite.svg';
    import './App.css';

    export function SatelliteViewer() {
      const globeRef = useRef<HTMLDivElement>(null);
      const transparent = true;
      const minDistance = 1.5;
      const RA_OF_ASC_NODE = 180;
      const MEAN_MOTION_DOT = 0.00003;

      useEffect(() => {
        if (globeRef.current) {
          console.log("Mounted");
        }
      }, []);

      return <div ref={globeRef} className="satellite-canvas" />;
    }
    """
    patterns = load_default_patterns()
    cfg = EnvGuardConfig()
    findings = scan_text(sample_code, "SatelliteViewer.tsx", patterns, advanced_config=cfg.advanced_detection)
    entropy_findings = [f for f in findings if f.rule_id == "generic-high-entropy-secret"]
    assert len(entropy_findings) == 0


def test_scanner_ignores_yara_and_api_names():
    """Security tools and malware analyzers with API constant names must not trigger entropy rule."""
    sample_analyzer = """
    EVASION_SIGNATURES = [
        "CreateProcessInternalW",
        "InternetConnectA",
        "HttpSendRequestExW",
        "AccessibilityPerformAction",
        "requests_sms_and_overlay_together",
    ]
    EVASION_TYPE = "ENVIRONMENT_CHECK"
    """
    patterns = load_default_patterns()
    cfg = EnvGuardConfig()
    findings = scan_text(sample_analyzer, "analyzer.py", patterns, advanced_config=cfg.advanced_detection)
    entropy_findings = [f for f in findings if f.rule_id == "generic-high-entropy-secret"]
    assert len(entropy_findings) == 0
