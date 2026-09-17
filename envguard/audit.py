"""Audit and Compliance Report Generator for EnvGuard v0.9.0.

Produces comprehensive, self-contained HTML (print-ready to PDF) and JSON audit reports
combining scan results, compliance framework mappings, configuration health, and historical trends.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import html
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from envguard import __version__
from envguard.compliance import ComplianceSummary, map_findings_to_compliance, COMPLIANCE_DISCLAIMER
from envguard.config_linter import ConfigLintReport, lint_configuration
from envguard.scanner import ScanFinding
from envguard.trend import BaselineTrendReport, compute_baseline_trend


@dataclass
class AuditMetadata:
    repo_name: str
    target_path: str
    scan_timestamp: str
    git_commit_sha: Optional[str] = None
    git_branch: Optional[str] = None
    envguard_version: str = __version__


@dataclass
class AuditReportData:
    metadata: AuditMetadata
    findings: List[ScanFinding]
    compliance: ComplianceSummary
    trend: BaselineTrendReport
    lint: ConfigLintReport

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "LOW")

    @property
    def posture_grade(self) -> str:
        """Calculate overall security posture grade from A to F."""
        if self.high_count > 0:
            return "F"
        if self.lint.error_count > 0:
            return "D"
        if self.medium_count > 2:
            return "C"
        if self.medium_count > 0 or self.low_count > 3:
            return "B"
        if self.low_count > 0 or self.lint.warning_count > 0:
            return "A-"
        return "A+"


def build_audit_data(
    target_root: Path,
    findings: List[ScanFinding],
    baseline_path: Optional[Path] = None,
) -> AuditReportData:
    """Collate scan findings, compliance mappings, configuration linting, and trends."""
    resolved_root = target_root.resolve()
    base_file = baseline_path or (resolved_root / ".envguard-baseline.json")

    # Git metadata
    from envguard.git_handler import get_repo_root, is_git_repo
    from envguard.git_utils import run_git

    repo_name = resolved_root.name
    commit_sha = None
    branch_name = None

    if is_git_repo(resolved_root):
        sha_proc = run_git(["rev-parse", "--short", "HEAD"], cwd=resolved_root)
        if sha_proc.returncode == 0:
            commit_sha = sha_proc.stdout.decode("utf-8").strip()
        br_proc = run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=resolved_root)
        if br_proc.returncode == 0:
            branch_name = br_proc.stdout.decode("utf-8").strip()

    meta = AuditMetadata(
        repo_name=repo_name,
        target_path=str(resolved_root),
        scan_timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        git_commit_sha=commit_sha,
        git_branch=branch_name,
    )

    compliance_summary = map_findings_to_compliance(findings)
    trend_report = compute_baseline_trend(findings, base_file)
    lint_report = lint_configuration(resolved_root)

    return AuditReportData(
        metadata=meta,
        findings=findings,
        compliance=compliance_summary,
        trend=trend_report,
        lint=lint_report,
    )


def generate_html_audit_report(data: AuditReportData) -> str:
    """Render a modern, standalone HTML document formatted for screen viewing and print-to-PDF."""
    grade = data.posture_grade
    grade_color = "#10b981" if "A" in grade else ("#3b82f6" if "B" in grade else ("#f59e0b" if "C" in grade else "#ef4444"))

    # Table rows for findings (Strictly using masked values, NEVER raw secrets)
    findings_rows = []
    for f in data.findings:
        sev_badge = f'<span class="badge badge-{f.severity.lower()}">{html.escape(f.severity)}</span>'
        findings_rows.append(
            f"<tr>"
            f"<td>{sev_badge}</td>"
            f"<td><code>{html.escape(f.rule_id)}</code></td>"
            f"<td><code>{html.escape(f.file_path)}:{f.line_number}</code></td>"
            f"<td><span class=\"secret-masked\">{html.escape(f.masked_value)}</span></td>"
            f"</tr>"
        )
    findings_tbody = "\n".join(findings_rows) if findings_rows else "<tr><td colspan='4' class='empty-row'>No secrets detected. Clean codebase!</td></tr>"

    # SOC 2 Rows
    soc2_rows = []
    for cid, ctrl in sorted(data.compliance.soc2_controls.items()):
        soc2_rows.append(
            f"<tr>"
            f"<td><strong>{html.escape(cid)}</strong></td>"
            f"<td>{html.escape(ctrl.title)}</td>"
            f"<td><span class='badge badge-count'>{ctrl.findings_count}</span></td>"
            f"<td>{html.escape(', '.join(sorted(ctrl.affected_rules)))}</td>"
            f"</tr>"
        )
    soc2_tbody = "\n".join(soc2_rows) if soc2_rows else "<tr><td colspan='4' class='empty-row'>Zero SOC 2 control violations detected.</td></tr>"

    # ISO 27001 Rows
    iso_rows = []
    for cid, ctrl in sorted(data.compliance.iso27001_controls.items()):
        iso_rows.append(
            f"<tr>"
            f"<td><strong>{html.escape(cid)}</strong></td>"
            f"<td>{html.escape(ctrl.title)}</td>"
            f"<td><span class='badge badge-count'>{ctrl.findings_count}</span></td>"
            f"<td>{html.escape(', '.join(sorted(ctrl.affected_rules)))}</td>"
            f"</tr>"
        )
    iso_tbody = "\n".join(iso_rows) if iso_rows else "<tr><td colspan='4' class='empty-row'>Zero ISO 27001 control violations detected.</td></tr>"

    # Lint Rows
    lint_rows = []
    for d in data.lint.diagnostics:
        badge = f'<span class="badge badge-{d.level.lower()}">{html.escape(d.level)}</span>'
        rec = f"<br><small class='text-dim'>{html.escape(d.recommendation)}</small>" if d.recommendation else ""
        lint_rows.append(
            f"<tr>"
            f"<td>{badge}</td>"
            f"<td><code>{html.escape(d.file or '-')}</code></td>"
            f"<td><code>{html.escape(d.field or '-')}</code></td>"
            f"<td>{html.escape(d.message)}{rec}</td>"
            f"</tr>"
        )
    lint_tbody = "\n".join(lint_rows) if lint_rows else "<tr><td colspan='4' class='empty-row'>Configuration validated with 0 diagnostics.</td></tr>"

    # Baseline Trend badge
    trend_label = data.trend.trend_direction
    trend_badge_class = "badge-pass" if trend_label == "IMPROVING" else ("badge-high" if trend_label == "DEGRADING" else "badge-low")

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EnvGuard Security & Compliance Audit Report — {html.escape(data.metadata.repo_name)}</title>
<style>
  :root {{
    --bg: #0f172a;
    --surface: #1e293b;
    --surface-alt: #334155;
    --text: #f8fafc;
    --text-dim: #94a3b8;
    --primary: #6366f1;
    --danger: #ef4444;
    --warning: #f59e0b;
    --success: #10b981;
    --info: #3b82f6;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
    padding: 2.5rem 2rem;
  }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 2px solid var(--surface-alt);
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
  }}
  .brand h1 {{ font-size: 1.75rem; font-weight: 700; color: #fff; letter-spacing: -0.025em; }}
  .brand p {{ color: var(--text-dim); font-size: 0.875rem; }}
  .meta-tags {{ text-align: right; font-size: 0.825rem; color: var(--text-dim); }}
  .meta-tags strong {{ color: var(--text); }}
  .posture-panel {{
    background: var(--surface);
    border-radius: 12px;
    padding: 1.5rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 2rem;
    border: 1px solid var(--surface-alt);
  }}
  .posture-grade-box {{
    display: flex;
    align-items: center;
    gap: 1.25rem;
  }}
  .grade-circle {{
    width: 68px;
    height: 68px;
    border-radius: 50%;
    background: {grade_color}22;
    border: 3px solid {grade_color};
    color: {grade_color};
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 2rem;
    font-weight: 800;
  }}
  .kpi-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    margin-bottom: 2rem;
  }}
  .kpi-card {{
    background: var(--surface);
    border: 1px solid var(--surface-alt);
    border-radius: 10px;
    padding: 1.25rem;
    text-align: center;
  }}
  .kpi-value {{ font-size: 2rem; font-weight: 800; color: #fff; }}
  .kpi-label {{ font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-dim); }}
  section {{
    background: var(--surface);
    border: 1px solid var(--surface-alt);
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 2rem;
  }}
  section h2 {{ font-size: 1.25rem; font-weight: 700; margin-bottom: 1rem; color: #fff; border-bottom: 1px solid var(--surface-alt); padding-bottom: 0.5rem; }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.875rem;
  }}
  th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.06); }}
  th {{ background: rgba(0,0,0,0.2); color: var(--text-dim); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; background: rgba(0,0,0,0.3); padding: 0.2rem 0.4rem; border-radius: 4px; font-size: 0.825rem; }}
  .badge {{
    display: inline-block;
    padding: 0.2rem 0.55rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
  }}
  .badge-high, .badge-error {{ background: #ef444422; color: #f87171; border: 1px solid #ef444466; }}
  .badge-medium, .badge-warning {{ background: #f59e0b22; color: #fbbf24; border: 1px solid #f59e0b66; }}
  .badge-low, .badge-info {{ background: #3b82f622; color: #60a5fa; border: 1px solid #3b82f666; }}
  .badge-pass {{ background: #10b98122; color: #34d399; border: 1px solid #10b98166; }}
  .badge-count {{ background: var(--surface-alt); color: #fff; }}
  .secret-masked {{ font-family: monospace; color: #38bdf8; font-weight: bold; }}
  .empty-row {{ text-align: center; color: var(--text-dim); padding: 2rem; }}
  .text-dim {{ color: var(--text-dim); }}
  .disclaimer-box {{
    background: rgba(245, 158, 11, 0.08);
    border: 1px solid rgba(245, 158, 11, 0.3);
    border-radius: 8px;
    padding: 1rem 1.25rem;
    font-size: 0.8rem;
    color: #fbbf24;
    margin-top: 2rem;
  }}
  @media print {{
    body {{ background: #fff; color: #000; padding: 0; }}
    .container {{ max-width: 100%; }}
    section, .posture-panel, .kpi-card {{ background: #fff; border: 1px solid #ccc; color: #000; break-inside: avoid; }}
    th {{ background: #f0f0f0; color: #333; }}
    th, td {{ border-bottom: 1px solid #ddd; }}
    code {{ background: #eee; color: #000; }}
    .brand h1, section h2, .kpi-value {{ color: #000; }}
    .grade-circle {{ background: #fff; }}
  }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="brand">
      <h1>EnvGuard Security &amp; Compliance Audit Report</h1>
      <p>Local-First Secret Governance and Framework Assurance &bull; v{html.escape(data.metadata.envguard_version)}</p>
    </div>
    <div class="meta-tags">
      <div>Repository: <strong>{html.escape(data.metadata.repo_name)}</strong></div>
      <div>Scanned: <strong>{html.escape(data.metadata.scan_timestamp)}</strong></div>
      <div>Commit: <strong>{html.escape(data.metadata.git_commit_sha or 'N/A')}</strong> ({html.escape(data.metadata.git_branch or 'N/A')})</div>
    </div>
  </header>

  <div class="posture-panel">
    <div class="posture-grade-box">
      <div class="grade-circle">{grade}</div>
      <div>
        <h2>Security Posture Grade: {grade}</h2>
        <p class="text-dim">Overall repository credential defense rating calculated from severity findings and policy assurance.</p>
      </div>
    </div>
    <div>
      <span class="badge {trend_badge_class}">Trend: {html.escape(trend_label)}</span>
    </div>
  </div>

  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-value">{len(data.findings)}</div>
      <div class="kpi-label">Total Findings</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-value" style="color: #f87171;">{data.high_count}</div>
      <div class="kpi-label">High Severity</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-value" style="color: #60a5fa;">{data.compliance.total_impacted_controls}</div>
      <div class="kpi-label">Controls Impacted</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-value" style="color: #34d399;">{data.trend.resolved_count}</div>
      <div class="kpi-label">Secrets Remediated</div>
    </div>
  </div>

  <section>
    <h2>Compliance Framework Alignment</h2>
    <h3 style="font-size: 1rem; margin: 1rem 0 0.5rem 0; color: #a5b4fc;">SOC 2 Type II Controls</h3>
    <table>
      <thead>
        <tr>
          <th style="width: 15%;">Control</th>
          <th style="width: 40%;">Title</th>
          <th style="width: 15%;">Violations</th>
          <th style="width: 30%;">Impacted Rules</th>
        </tr>
      </thead>
      <tbody>
        {soc2_tbody}
      </tbody>
    </table>

    <h3 style="font-size: 1rem; margin: 1.5rem 0 0.5rem 0; color: #a5b4fc;">ISO/IEC 27001:2022 Controls</h3>
    <table>
      <thead>
        <tr>
          <th style="width: 15%;">Control</th>
          <th style="width: 40%;">Title</th>
          <th style="width: 15%;">Violations</th>
          <th style="width: 30%;">Impacted Rules</th>
        </tr>
      </thead>
      <tbody>
        {iso_tbody}
      </tbody>
    </table>
  </section>

  <section>
    <h2>Historical Trend (Baseline Snapshot Delta)</h2>
    <table>
      <thead>
        <tr>
          <th>Category</th>
          <th>Count</th>
          <th>Description</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><span class="badge badge-error">New Drift</span></td>
          <td><strong>{len(data.trend.new_findings)}</strong></td>
          <td>Newly introduced credentials not present in baseline snapshot.</td>
        </tr>
        <tr>
          <td><span class="badge badge-pass">Resolved</span></td>
          <td><strong>{data.trend.resolved_count}</strong></td>
          <td>Credentials successfully purged/remediated since baseline snapshot.</td>
        </tr>
        <tr>
          <td><span class="badge badge-warning">Persistent Debt</span></td>
          <td><strong>{len(data.trend.persistent_findings)}</strong></td>
          <td>Legacy credentials present in baseline snapshot and still active.</td>
        </tr>
      </tbody>
    </table>
  </section>

  <section>
    <h2>Configuration Assurance &amp; Policy Health</h2>
    <table>
      <thead>
        <tr>
          <th style="width: 12%;">Status</th>
          <th style="width: 20%;">File</th>
          <th style="width: 20%;">Directive / Field</th>
          <th style="width: 48%;">Diagnostic &amp; Action</th>
        </tr>
      </thead>
      <tbody>
        {lint_tbody}
      </tbody>
    </table>
  </section>

  <section>
    <h2>Detected Secret Findings (Pre-Masked)</h2>
    <table>
      <thead>
        <tr>
          <th style="width: 12%;">Severity</th>
          <th style="width: 25%;">Rule</th>
          <th style="width: 38%;">Location</th>
          <th style="width: 25%;">Masked Token</th>
        </tr>
      </thead>
      <tbody>
        {findings_tbody}
      </tbody>
    </table>
  </section>

  <div class="disclaimer-box">
    <strong>Auditing Disclaimer:</strong> {html.escape(data.compliance.disclaimer)}
  </div>
</div>
</body>
</html>
"""
    return html_content


def generate_audit_json(data: AuditReportData) -> Dict[str, Any]:
    """Generate structured JSON representation of the full audit report."""
    return {
        "version": data.metadata.envguard_version,
        "command": "audit",
        "metadata": {
            "repository": data.metadata.repo_name,
            "target_path": data.metadata.target_path,
            "scan_timestamp": data.metadata.scan_timestamp,
            "git_commit_sha": data.metadata.git_commit_sha,
            "git_branch": data.metadata.git_branch,
        },
        "posture": {
            "grade": data.posture_grade,
            "total_findings": len(data.findings),
            "high_severity": data.high_count,
            "medium_severity": data.medium_count,
            "low_severity": data.low_count,
            "trend": data.trend.trend_direction,
        },
        "compliance": {
            "disclaimer": data.compliance.disclaimer,
            "impacted_frameworks_count": data.compliance.impacted_frameworks_count,
            "soc2": {
                cid: {
                    "title": c.title,
                    "violations_count": c.findings_count,
                    "affected_rules": sorted(c.affected_rules),
                }
                for cid, c in data.compliance.soc2_controls.items()
            },
            "iso27001": {
                cid: {
                    "title": c.title,
                    "violations_count": c.findings_count,
                    "affected_rules": sorted(c.affected_rules),
                }
                for cid, c in data.compliance.iso27001_controls.items()
            },
        },
        "trend": {
            "baseline_exists": data.trend.baseline_exists,
            "baseline_count": data.trend.baseline_count,
            "current_count": data.trend.current_count,
            "new_count": len(data.trend.new_findings),
            "resolved_count": data.trend.resolved_count,
            "persistent_count": len(data.trend.persistent_findings),
            "remediation_rate_pct": data.trend.remediation_rate_pct,
        },
        "configuration_lint": {
            "clean": data.lint.is_clean,
            "error_count": data.lint.error_count,
            "warning_count": data.lint.warning_count,
            "diagnostics": [
                {
                    "file": d.file,
                    "field": d.field,
                    "level": d.level,
                    "message": d.message,
                    "recommendation": d.recommendation,
                }
                for d in data.lint.diagnostics
            ],
        },
        "findings": [
            {
                "file": f.file_path,
                "line": f.line_number,
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": f.severity,
                "masked_value": f.masked_value,
            }
            for f in data.findings
        ],
    }
