"""Local detection of secrets-manager integration patterns for EnvGuard v0.8.0.

Provides 100% local, offline inspection to identify code referencing:
- AWS Secrets Manager (boto3, botocore, secretsmanager)
- HashiCorp Vault (hvac, vault client)
- Azure Key Vault (azure.keyvault.secrets, SecretClient)
- Google Cloud Secret Manager (google.cloud.secretmanager, SecretManagerServiceClient)
- Standard Environment lookups (os.environ, os.getenv)

Zero network calls. Zero cloud telemetry.
"""

import re
from typing import Optional, Tuple


SECRETS_MANAGER_PATTERNS = [
    # AWS Secrets Manager
    (
        "aws_secrets_manager",
        "AWS Secrets Manager",
        re.compile(r"(?i)(?:boto3\.client\(\s*['\"]secretsmanager['\"]\s*\)|get_secret_value\s*\(|secretsmanager:GetSecretValue|aws_secretsmanager)"),
    ),
    # HashiCorp Vault
    (
        "hashicorp_vault",
        "HashiCorp Vault",
        re.compile(r"(?i)(?:hvac\.Client|client\.secrets\.kv|vault\.read\(|VAULT_ADDR|VAULT_TOKEN)"),
    ),
    # Azure Key Vault
    (
        "azure_key_vault",
        "Azure Key Vault",
        re.compile(r"(?i)(?:azure\.keyvault\.secrets|SecretClient\s*\(|get_secret\s*\()"),
    ),
    # Google Cloud Secret Manager
    (
        "gcp_secret_manager",
        "GCP Secret Manager",
        re.compile(r"(?i)(?:google\.cloud(?:\.secretmanager|\s+import\s+secretmanager)|SecretManagerServiceClient|access_secret_version)"),
    ),
    # Environment lookups
    (
        "environment_variable",
        "Environment Lookup",
        re.compile(r"(?i)(?:os\.environ\.get\s*\(|os\.environ\[|os\.getenv\s*\()"),
    ),
]


def detect_secrets_manager_reference(line: str) -> Optional[Tuple[str, str]]:
    """Inspect a line of code or snippet for secrets-manager patterns.

    Returns:
        (manager_id, manager_name) if detected, else None.
    """
    if not line:
        return None

    for mgr_id, mgr_name, pattern in SECRETS_MANAGER_PATTERNS:
        if pattern.search(line):
            return mgr_id, mgr_name

    return None
