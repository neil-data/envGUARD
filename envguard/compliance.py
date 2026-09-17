"""Compliance Mapping Engine for EnvGuard v0.9.0.

Provides offline, local cross-referencing between EnvGuard secret detection rules
and established cybersecurity and compliance frameworks (SOC 2 Type II, ISO/IEC 27001:2022).
"""

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from envguard.scanner import ScanFinding

COMPLIANCE_SCHEMA_VERSION = 1

COMPLIANCE_DISCLAIMER = (
    "These mappings are informational control cross-references for security posture assessment "
    "and internal auditing. They do NOT constitute formal compliance certification, legal advice, "
    "or guarantee of regulatory approval."
)

_COMPLIANCE_CACHE: Optional[Dict[str, Any]] = None


def get_compliance_data_path() -> Path:
    """Return the path to the bundled compliance mappings JSON file."""
    return Path(__file__).resolve().parent / "data" / "compliance.json"


def load_compliance_mappings() -> Dict[str, Any]:
    """Load and cache the versioned compliance mappings data."""
    global _COMPLIANCE_CACHE
    if _COMPLIANCE_CACHE is not None:
        return _COMPLIANCE_CACHE

    path = get_compliance_data_path()
    if not path.is_file():
        # Fallback if bundled file missing
        return {
            "schema_version": COMPLIANCE_SCHEMA_VERSION,
            "disclaimer": COMPLIANCE_DISCLAIMER,
            "frameworks": {},
            "rule_mappings": {},
        }

    try:
        content = path.read_text(encoding="utf-8-sig")
        data = json.loads(content)
        _COMPLIANCE_CACHE = data
        return data
    except Exception:
        return {
            "schema_version": COMPLIANCE_SCHEMA_VERSION,
            "disclaimer": COMPLIANCE_DISCLAIMER,
            "frameworks": {},
            "rule_mappings": {},
        }


def get_rule_compliance(rule_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve compliance categories and control mappings for a specific rule ID."""
    mappings = load_compliance_mappings()
    rule_map = mappings.get("rule_mappings", {})
    if rule_id in rule_map:
        return rule_map[rule_id]
    # Check normalized forms (e.g. aws_key -> aws-access-key or aws_access_key -> aws-access-key)
    norm = rule_id.lower().replace("_", "-")
    if norm in rule_map:
        return rule_map[norm]
    # Check if prefix match or partial match
    for k, v in rule_map.items():
        if norm.startswith(k) or k.startswith(norm):
            return v
    return None


@dataclass
class ControlImpact:
    control_id: str
    title: str
    framework_id: str
    framework_name: str
    findings_count: int = 0
    high_count: int = 0
    med_count: int = 0
    low_count: int = 0
    affected_rules: Set[str] = field(default_factory=set)


@dataclass
class ComplianceSummary:
    total_findings: int
    impacted_frameworks_count: int
    disclaimer: str = COMPLIANCE_DISCLAIMER
    soc2_controls: Dict[str, ControlImpact] = field(default_factory=dict)
    iso27001_controls: Dict[str, ControlImpact] = field(default_factory=dict)
    category_breakdown: Dict[str, int] = field(default_factory=dict)

    @property
    def total_impacted_controls(self) -> int:
        return len(self.soc2_controls) + len(self.iso27001_controls)


def map_findings_to_compliance(findings: List[ScanFinding]) -> ComplianceSummary:
    """Analyze a collection of scan findings and aggregate compliance impacts."""
    data = load_compliance_mappings()
    frameworks = data.get("frameworks", {})
    rule_mappings = data.get("rule_mappings", {})

    soc2_meta = frameworks.get("soc2", {}).get("controls", {})
    iso_meta = frameworks.get("iso27001", {}).get("controls", {})

    summary = ComplianceSummary(
        total_findings=len(findings),
        impacted_frameworks_count=0,
        disclaimer=data.get("disclaimer", COMPLIANCE_DISCLAIMER),
    )

    for f in findings:
        mapping = get_rule_compliance(f.rule_id)
        if not mapping:
            # Check for generic fallback based on pattern name or category
            continue

        cat = mapping.get("category", "General Secret Exposure")
        summary.category_breakdown[cat] = summary.category_breakdown.get(cat, 0) + 1

        controls = mapping.get("controls", {})

        # SOC 2
        for cid in controls.get("soc2", []):
            if cid not in summary.soc2_controls:
                meta = soc2_meta.get(cid, {})
                summary.soc2_controls[cid] = ControlImpact(
                    control_id=cid,
                    title=meta.get("title", cid),
                    framework_id="soc2",
                    framework_name="SOC 2 Type II",
                )
            ctrl = summary.soc2_controls[cid]
            ctrl.findings_count += 1
            ctrl.affected_rules.add(f.rule_id)
            if f.severity == "HIGH":
                ctrl.high_count += 1
            elif f.severity == "MEDIUM":
                ctrl.med_count += 1
            else:
                ctrl.low_count += 1

        # ISO 27001
        for cid in controls.get("iso27001", []):
            if cid not in summary.iso27001_controls:
                meta = iso_meta.get(cid, {})
                summary.iso27001_controls[cid] = ControlImpact(
                    control_id=cid,
                    title=meta.get("title", cid),
                    framework_id="iso27001",
                    framework_name="ISO/IEC 27001:2022",
                )
            ctrl = summary.iso27001_controls[cid]
            ctrl.findings_count += 1
            ctrl.affected_rules.add(f.rule_id)
            if f.severity == "HIGH":
                ctrl.high_count += 1
            elif f.severity == "MEDIUM":
                ctrl.med_count += 1
            else:
                ctrl.low_count += 1

    framework_count = 0
    if summary.soc2_controls:
        framework_count += 1
    if summary.iso27001_controls:
        framework_count += 1
    summary.impacted_frameworks_count = framework_count

    return summary
