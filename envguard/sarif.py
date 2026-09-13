"""SARIF (Static Analysis Results Interchange Format) v2.1.0 generator for EnvGuard v0.5.3.

Provides standard SARIF output compatible with GitHub Code Scanning, IDEs, and DevSecOps pipelines.
Guarantees 100% privacy: plain-text secrets are strictly never included in SARIF outputs.
"""

from typing import Any, Dict, List, Optional

from envguard.patterns import Pattern, load_default_patterns
from envguard.scanner import ScanFinding

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
ENVGUARD_INFO_URI = "https://github.com/neil-data/envGUARD"

SEVERITY_TO_SARIF_LEVEL = {
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def severity_to_level(sev: str) -> str:
    """Map EnvGuard severity to SARIF level (error, warning, note)."""
    return SEVERITY_TO_SARIF_LEVEL.get(sev.upper(), "warning")


def generate_sarif(
    findings: List[ScanFinding],
    tool_version: str,
    patterns: Optional[List[Pattern]] = None,
) -> Dict[str, Any]:
    """Generate a standard SARIF v2.1.0 report dictionary from scan findings.

    Plaintext secrets are NEVER included in messages or metadata.
    """
    rule_catalog: Dict[str, Pattern] = {}
    default_patterns = patterns or load_default_patterns()
    for p in default_patterns:
        rule_catalog[p.id] = p

    # Collect unique rule IDs from patterns and findings
    seen_rule_ids = set(rule_catalog.keys())
    for f in findings:
        seen_rule_ids.add(f.rule_id)

    rules_list: List[Dict[str, Any]] = []
    for r_id in sorted(seen_rule_ids):
        p = rule_catalog.get(r_id)
        if p:
            short_desc = p.description or p.name
            full_desc = p.detects or p.description or p.name
            help_text = f"{p.why_it_matters}\n\nRemediation:\n{p.remediation}"
            default_level = severity_to_level(p.severity)
            rule_name = p.name
        else:
            rule_name = r_id.replace("-", " ").title()
            short_desc = f"Secret detected by rule {r_id}"
            full_desc = short_desc
            help_text = "Remove credential from source control and store in environment variables or vault."
            default_level = "warning"

        rule_entry: Dict[str, Any] = {
            "id": r_id,
            "name": rule_name,
            "shortDescription": {"text": short_desc},
            "fullDescription": {"text": full_desc},
            "defaultConfiguration": {
                "level": default_level,
            },
            "help": {
                "text": help_text,
            },
            "properties": {
                "tags": ["security", "credentials", "secrets"],
            },
        }
        rules_list.append(rule_entry)

    # Build results list
    results_list: List[Dict[str, Any]] = []
    for f in findings:
        level = severity_to_level(f.severity)
        normalized_path = f.file_path.replace("\\", "/")

        # Safe message: rule and file location, never the raw secret
        safe_msg = f"Potential secret detected matching rule '{f.rule_id}' ({f.rule_name})."

        result_entry: Dict[str, Any] = {
            "ruleId": f.rule_id,
            "level": level,
            "message": {
                "text": safe_msg,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": normalized_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": max(1, f.line_number),
                        },
                    }
                }
            ],
            "properties": {
                "maskedValue": f.masked_value,
                "fingerprint": f.fingerprint,
                **({"entropy": f.entropy} if getattr(f, "entropy", None) is not None else {}),
                **({"provider": f.provider} if getattr(f, "provider", None) else {}),
                **({"signals": f.detection_signals} if getattr(f, "detection_signals", None) else {}),
            },
        }
        results_list.append(result_entry)

    sarif_doc: Dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "EnvGuard",
                        "semanticVersion": tool_version,
                        "informationUri": ENVGUARD_INFO_URI,
                        "rules": rules_list,
                    }
                },
                "results": results_list,
            }
        ],
    }

    return sarif_doc
