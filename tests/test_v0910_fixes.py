"""Comprehensive regression tests for EnvGuard v0.9.10 fixes:
- Bug #1: False-positive explosion in generic-high-entropy-secret
- Bug #4: Config linter rejection of documented CI, reporting, and advanced_detection keys
- Bug #5: Audit treating baseline suppression as 100% remediation
"""

from dataclasses import dataclass
import json
from pathlib import Path
import pytest

from envguard.config import EnvGuardConfig, ReportingConfig, CIConfig, load_config, load_raw_config_file
from envguard.config_linter import lint_configuration, lint_single_file, get_known_rule_ids
from envguard.detectors.entropy_detector import detect_entropy_candidates
from envguard.detectors.scoring import AdvancedDetectionConfig
from envguard.patterns import Pattern, load_default_patterns
from envguard.scanner import ScanFinding, compute_legacy_fingerprint, compute_fingerprint, scan_file_streaming
from envguard.trend import compute_baseline_trend, BaselineTrendReport
from envguard.audit import build_audit_data, generate_audit_json, generate_html_audit_report
from envguard.initializer import default_envguard_yml


# ==============================================================================
# Bug #1: High Entropy FP Elimination & Precision Tests
# ==============================================================================

class TestHighEntropyPrecision:
    """Ensure generic-high-entropy-secret ignores non-secrets and keeps real secrets."""

    @pytest.fixture
    def config(self):
        return AdvancedDetectionConfig()

    def test_exempt_lockfile_paths(self, config):
        lockfiles = [
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "Cargo.lock",
            "composer.lock",
            "poetry.lock",
            "Pipfile.lock",
            "go.sum",
            "gradle.lockfile",
            "podfile.lock",
            "sub/dir/package-lock.json",
        ]
        line = '    "integrity": "sha512-4aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890/abcdefghijklmnopqrstuvwxyz=="'
        for lf in lockfiles:
            matches = detect_entropy_candidates(line, 1, lf, config)
            assert matches == [], f"Lockfile '{lf}' should be exempt from high-entropy detector"

    def test_exempt_css_files(self, config):
        css_files = ["styles.css", "app.scss", "theme.less", "main.sass", "ui.styl", "styles.pcss"]
        line = "  --tw-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);"
        for cf in css_files:
            matches = detect_entropy_candidates(line, 5, cf, config)
            assert matches == [], f"CSS file '{cf}' should be exempt from high-entropy detector"

    def test_exempt_docs_and_fixtures(self, config):
        doc_files = ["docs/setup.md", "README.rst", "doc/manual.adoc", "notes.txt"]
        line = 'Example token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummyPayloadText12345"'
        for df in doc_files:
            matches = detect_entropy_candidates(line, 10, df, config)
            assert matches == [], f"Doc file '{df}' should be exempt from high-entropy detector"

        fixture_files = [
            "tests/fixtures/mock_data.json",
            "testdata/sample.xml",
            "spec/test_fixtures/blob.dat",
            "mocks/response.json",
            "test-data/users.json",
            "sample.fixture",
            "snapshot.snap",
        ]
        for ff in fixture_files:
            matches = detect_entropy_candidates(line, 12, ff, config)
            assert matches == [], f"Fixture file '{ff}' should be exempt from high-entropy detector"

    def test_exempt_yara_and_reports(self, config):
        exempt = ["rules/detection.yar", "malware.yara", "audit-report.sarif", "results_report.json"]
        line = '$rule_hash = "9f83c211b4359196b8f111558a2d765723765123456789abcdef"'
        for ef in exempt:
            matches = detect_entropy_candidates(line, 20, ef, config)
            assert matches == [], f"Exempt file '{ef}' should not be scanned by high-entropy detector"

    def test_non_secret_tokens_in_code(self, config):
        file_path = "app/services.py"

        # Android permission string
        line_perm = 'Manifest.permission.BIND_QUICK_SETTINGS_TILE = "android.permission.BIND_QUICK_SETTINGS_TILE"'
        assert detect_entropy_candidates(line_perm, 1, file_path, config) == []

        # Reverse-domain package identifier
        line_pkg = 'package_name = "com.google.android.gms.measurement.AppMeasurement"'
        assert detect_entropy_candidates(line_pkg, 2, file_path, config) == []

        # CSS style inline
        line_css = 'style = "border-color: #f3f4f6; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);"'
        assert detect_entropy_candidates(line_css, 3, file_path, config) == []

        # Shell variable / flag
        line_sh = 'cmd = "export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-default_value}"'
        assert detect_entropy_candidates(line_sh, 4, file_path, config) == []

        # File path / import
        line_path = 'import_path = "components/authentication/AuthenticationProviderManager.tsx"'
        assert detect_entropy_candidates(line_path, 5, file_path, config) == []

        # Function / API identifier
        line_func = 'result = processEnterpriseCustomerSubscriptionInvoiceBillingRecord()'
        assert detect_entropy_candidates(line_func, 6, file_path, config) == []

    def test_real_high_entropy_secret_detected(self, config, tmp_path):
        file_path = "app/config.py"
        # Genuine secret in credential context with random high-entropy value
        line = 'api_secret_key = "aZ9#kL2$vX8@mP4!qW7&jR1*tY5^sB0="'
        matches = detect_entropy_candidates(line, 15, file_path, config)
        assert len(matches) == 1
        assert matches[0].rule_id == "generic-high-entropy-secret"
        assert matches[0].source == "entropy"

        # End-to-end scan verification
        test_file = tmp_path / "secrets.py"
        test_file.write_text(f"{line}\n", encoding="utf-8")
        findings, _ = scan_file_streaming(
            file_path=test_file,
            rel_path_str="secrets.py",
            patterns=[],
            advanced_config=config,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "generic-high-entropy-secret"
        assert findings[0].severity == "MEDIUM"


# ==============================================================================
# Bug #4: Config Linter Validation Tests
# ==============================================================================

class TestConfigLinterDocumentedKeys:
    """Ensure config linter and loader accept all documented keys."""

    def test_default_initializer_config_lints_clean(self, tmp_path):
        cfg_path = tmp_path / ".envguard.yml"
        cfg_path.write_text(default_envguard_yml, encoding="utf-8")

        report = lint_configuration(tmp_path)
        assert report.error_count == 0, f"Errors: {[d.message for d in report.diagnostics if d.level == 'ERROR']}"
        assert report.warning_count == 0, f"Warnings: {[d.message for d in report.diagnostics if d.level == 'WARNING']}"
        assert report.is_clean

    def test_ci_annotations_and_job_summary(self, tmp_path):
        yml_content = """version: 1
ci:
  changed_files_only: true
  base_branch: "main"
  annotations: true
  job_summary: true
  emit_annotations: true
  step_summary: true
  fail_on_warning: false
"""
        cfg_path = tmp_path / ".envguard.yml"
        cfg_path.write_text(yml_content, encoding="utf-8")

        cfg = load_raw_config_file(cfg_path)
        assert cfg.ci.annotations is True
        assert cfg.ci.job_summary is True
        assert cfg.ci.changed_files_only is True

        report = lint_configuration(tmp_path)
        assert report.error_count == 0
        assert report.warning_count == 0

    def test_reporting_section_keys(self, tmp_path):
        yml_content = """version: 1
reporting:
  color: true
  show_fingerprints: false
  format: "json"
  output: "audit-report.json"
"""
        cfg_path = tmp_path / ".envguard.yml"
        cfg_path.write_text(yml_content, encoding="utf-8")

        cfg = load_raw_config_file(cfg_path)
        assert isinstance(cfg.reporting, ReportingConfig)
        assert cfg.reporting.color is True
        assert cfg.reporting.show_fingerprints is False
        assert cfg.reporting.format == "json"
        assert cfg.reporting.output == "audit-report.json"

        report = lint_configuration(tmp_path)
        assert report.error_count == 0
        assert report.warning_count == 0

    def test_advanced_detection_sub_dictionaries(self, tmp_path):
        yml_content = """version: 1
advanced_detection:
  entropy:
    enabled: true
    min_length: 24
    threshold: 4.2
  jwt:
    enabled: true
  context_analysis:
    enabled: true
"""
        cfg_path = tmp_path / ".envguard.yml"
        cfg_path.write_text(yml_content, encoding="utf-8")

        cfg = load_raw_config_file(cfg_path)
        assert cfg.advanced_detection.entropy_enabled is True
        assert cfg.advanced_detection.entropy_min_length == 24
        assert cfg.advanced_detection.entropy_threshold == 4.2
        assert cfg.advanced_detection.jwt_enabled is True
        assert cfg.advanced_detection.context_enabled is True

        report = lint_configuration(tmp_path)
        assert report.error_count == 0
        assert report.warning_count == 0

    def test_linter_catches_actual_invalid_keys(self, tmp_path):
        yml_content = """version: 1
ci:
  invalid_ci_setting: true
reporting:
  invalid_reporting_setting: 123
"""
        cfg_path = tmp_path / ".envguard.yml"
        cfg_path.write_text(yml_content, encoding="utf-8")

        report = lint_configuration(tmp_path)
        warning_fields = [d.field for d in report.diagnostics if d.level == "WARNING"]
        assert "ci.invalid_ci_setting" in warning_fields
        assert "reporting.invalid_reporting_setting" in warning_fields


# ==============================================================================
# Bug #5: Audit Baseline Trend & Accurate Remediation Rate Tests
# ==============================================================================

class TestAuditBaselineTruthfulMetrics:
    """Ensure baseline suppressed debt is never misclassified as 100% resolved."""

    def _make_finding(self, rule_id: str, file_path: str, line: int, secret: str) -> ScanFinding:
        fp = compute_fingerprint(rule_id, file_path, secret)
        return ScanFinding(
            rule_id=rule_id,
            rule_name="Test Rule",
            severity="HIGH",
            file_path=file_path,
            line_number=line,
            raw_value=secret,
            masked_value=secret[:2] + "..." + secret[-2:],
            fingerprint=fp,
        )

    def test_baseline_suppression_is_zero_percent_resolved_when_findings_exist(self, tmp_path):
        # Create 3 findings
        f1 = self._make_finding("generic-api-key", "app/api.py", 10, "super_secret_api_key_111")
        f2 = self._make_finding("aws-secret-access-key", "config/aws.py", 20, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        f3 = self._make_finding("github-pat", "ci/deploy.py", 30, "ghp_123456789012345678901234567890123456")
        all_findings = [f1, f2, f3]

        # Create baseline containing all 3
        baseline_file = tmp_path / ".envguard-baseline.json"
        baseline_data = {
            "version": 1,
            "findings": [
                {"fingerprint": f1.fingerprint, "rule_id": f1.rule_id, "file": f1.file_path, "line": f1.line_number},
                {"fingerprint": f2.fingerprint, "rule_id": f2.rule_id, "file": f2.file_path, "line": f2.line_number},
                {"fingerprint": f3.fingerprint, "rule_id": f3.rule_id, "file": f3.file_path, "line": f3.line_number},
            ],
        }
        baseline_file.write_text(json.dumps(baseline_data), encoding="utf-8")

        # Compute trend when all 3 findings STILL exist in code
        trend = compute_baseline_trend(all_findings, baseline_file)

        assert trend.baseline_exists is True
        assert trend.baseline_count == 3
        assert trend.current_count == 3
        assert len(trend.new_findings) == 0
        assert len(trend.persistent_findings) == 3
        assert trend.resolved_count == 0, "All findings exist in codebase; resolved_count must be 0!"
        assert trend.remediation_rate_pct == 0.0, "Remediation rate must be 0.0% when nothing is resolved!"
        assert trend.trend_direction == "STABLE"

    def test_legacy_baseline_fingerprint_matching(self, tmp_path):
        # Create a finding
        f = self._make_finding("generic-api-key", "app/legacy.py", 15, "legacy_secret_token_12345")
        # Legacy fingerprint was sha256(rule:file:secret)
        legacy_fp = compute_legacy_fingerprint(f.rule_id, f.file_path, f.raw_value)

        baseline_file = tmp_path / ".envguard-baseline.json"
        baseline_data = {
            "version": 1,
            "findings": [
                {"fingerprint": legacy_fp, "rule_id": f.rule_id, "file": f.file_path, "line": f.line_number},
            ],
        }
        baseline_file.write_text(json.dumps(baseline_data), encoding="utf-8")

        # When scanning with finding f (whose f.fingerprint is canonical sha256(rule:secret)),
        # it must match via legacy fingerprint and be counted as persistent debt, NOT resolved!
        trend = compute_baseline_trend([f], baseline_file)

        assert len(trend.persistent_findings) == 1
        assert trend.resolved_count == 0
        assert trend.remediation_rate_pct == 0.0
        assert trend.trend_direction == "STABLE"

    def test_actual_remediation_when_secrets_removed(self, tmp_path):
        f1 = self._make_finding("generic-api-key", "app/api.py", 10, "secret_key_one_111111111")
        f2 = self._make_finding("aws-secret-key", "app/aws.py", 20, "secret_key_two_222222222")

        baseline_file = tmp_path / ".envguard-baseline.json"
        baseline_data = {
            "version": 1,
            "findings": [
                {"fingerprint": f1.fingerprint, "rule_id": f1.rule_id, "file": f1.file_path, "line": f1.line_number},
                {"fingerprint": f2.fingerprint, "rule_id": f2.rule_id, "file": f2.file_path, "line": f2.line_number},
            ],
        }
        baseline_file.write_text(json.dumps(baseline_data), encoding="utf-8")

        # Secret f2 was deleted! Only f1 remains in codebase.
        trend = compute_baseline_trend([f1], baseline_file)

        assert trend.baseline_count == 2
        assert trend.current_count == 1
        assert len(trend.persistent_findings) == 1
        assert len(trend.new_findings) == 0
        assert trend.resolved_count == 1, "f2 was purged from codebase, so resolved_count must be 1"
        assert trend.remediation_rate_pct == 50.0
        assert trend.trend_direction == "IMPROVING"

    def test_audit_json_and_html_generation(self, tmp_path):
        f = self._make_finding("generic-api-key", "app/auth.py", 5, "active_secret_key_xyz987")
        baseline_file = tmp_path / ".envguard-baseline.json"
        baseline_data = {
            "version": 1,
            "findings": [
                {"fingerprint": f.fingerprint, "rule_id": f.rule_id, "file": f.file_path, "line": f.line_number},
            ],
        }
        baseline_file.write_text(json.dumps(baseline_data), encoding="utf-8")

        audit_data = build_audit_data(tmp_path, [f], baseline_file)
        audit_json = generate_audit_json(audit_data)

        assert audit_json["trend"]["resolved_count"] == 0
        assert audit_json["trend"]["persistent_count"] == 1
        assert audit_json["trend"]["remediation_rate_pct"] == 0.0

        html_report = generate_html_audit_report(audit_data)
        assert "Persistent Debt" in html_report
        assert "Resolved" in html_report
