"""Unit tests for expanded cloud/provider detection rules."""

from envguard.patterns import load_default_patterns
from envguard.scanner import scan_text


def test_aws_secret_access_key(patterns):
    # Construct dynamically to avoid static scan push alarms
    prefix = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY"
    suffix = "EXAMPLEKEY"
    sample = f"AWS_SECRET_ACCESS_KEY={prefix}{suffix}"
    findings = scan_text(sample, "aws.env", patterns)
    aws_secret = [f for f in findings if f.rule_id == "aws-secret-access-key"]
    assert len(aws_secret) == 1
    assert aws_secret[0].severity == "HIGH"


def test_google_api_key(patterns):
    sample = "GOOGLE_API_KEY=" + "AIzaSy" + "A1234567890abcdefghijklmnopqrstuv"
    findings = scan_text(sample, "google.env", patterns)
    g_findings = [f for f in findings if f.rule_id == "google-api-key"]
    assert len(g_findings) == 1
    assert g_findings[0].severity in ("HIGH", "MEDIUM")


def test_google_service_account_context_required(patterns):
    alone = '{\n  "type": "service_account"\n}'
    f_alone = scan_text(alone, "creds.json", patterns)
    assert not any(f.rule_id == "google-service-account-key" for f in f_alone)

    full = '''
    {
      "type": "service_account",
      "project_id": "my-project",
      "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgk...",
      "client_email": "sa@my-project.iam.gserviceaccount.com"
    }
    '''
    f_full = scan_text(full, "sa_key.json", patterns)
    assert any(f.rule_id == "google-service-account-key" for f in f_full)


def test_azure_storage_connection_string(patterns):
    p1 = "DefaultEndpointsProtocol=https;AccountName=myacc;AccountKey="
    key_part = "a" * 86 + "=="
    p2 = ";EndpointSuffix=core.windows.net"
    sample = f"AZURE_STORAGE_CONN={p1}{key_part}{p2}"
    findings = scan_text(sample, "azure.env", patterns)
    az = [f for f in findings if f.rule_id == "azure-storage-connection-string"]
    assert len(az) == 1
    assert az[0].severity == "HIGH"


def test_gitlab_token(patterns):
    token = "glpat-" + "1234567890abcdefghij"
    sample = f"GITLAB_TOKEN={token}"
    findings = scan_text(sample, "gitlab.env", patterns)
    gl = [f for f in findings if f.rule_id == "gitlab-token"]
    assert len(gl) == 1
    assert gl[0].severity == "HIGH"


def test_npm_token(patterns):
    token = "npm_" + "1234567890abcdefghijklmnopqrstuvwxyz"
    sample = f"npm_token = '{token}'"
    findings = scan_text(sample, "npm.env", patterns)
    npm = [f for f in findings if f.rule_id == "npm-token"]
    assert len(npm) == 1
    assert npm[0].severity == "HIGH"


def test_pypi_token(patterns):
    token = "pypi-" + "A" * 120
    sample = f"PYPI_TOKEN={token}"
    findings = scan_text(sample, "pypi.env", patterns)
    pypi = [f for f in findings if f.rule_id == "pypi-token"]
    assert len(pypi) == 1
    assert pypi[0].severity == "HIGH"


def test_slack_token(patterns):
    token = "xox" + "b-" + "123456789012-1234567890123-abcdefghijklmnopqrstuvwx"
    sample = f"SLACK_BOT_TOKEN={token}"
    findings = scan_text(sample, "slack.env", patterns)
    sl = [f for f in findings if f.rule_id == "slack-token"]
    assert len(sl) == 1
    assert sl[0].severity == "HIGH"


def test_discord_token(patterns):
    token = "MT" + "A1MjU5ODQwNjAxOTI5OTM4OA" + "." + "G9xYZa" + "." + "1234567890abcdefghijklmnopqrstuvwx"
    sample = f"DISCORD_TOKEN={token}"
    findings = scan_text(sample, "bot.env", patterns)
    dc = [f for f in findings if f.rule_id == "discord-token"]
    assert len(dc) == 1
    assert dc[0].severity in ("HIGH", "MEDIUM")
