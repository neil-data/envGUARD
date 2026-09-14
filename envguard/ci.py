"""CI/CD environment detection for EnvGuard v0.5.5.

Detects running CI environments (GitHub Actions, GitLab CI, CircleCI, Jenkins,
Azure Pipelines, or Generic CI) and extracts pipeline metadata safely.
Runs 100% locally with zero network calls or telemetry.
"""

from dataclasses import dataclass
import os
from typing import Dict, Optional


@dataclass
class CIEnvironment:
    """Metadata representing the detected execution environment."""

    is_ci: bool
    provider: str  # "github", "gitlab", "circleci", "jenkins", "azure", "generic", "local"
    repository: Optional[str] = None
    branch: Optional[str] = None
    commit_sha: Optional[str] = None
    pull_request: Optional[str] = None
    base_ref: Optional[str] = None
    head_ref: Optional[str] = None


def detect_ci_environment(env: Optional[Dict[str, str]] = None) -> CIEnvironment:
    """Detect whether EnvGuard is running inside a CI environment and identify provider.

    Safely inspects environment variables without throwing exceptions when variables
    are missing or unset.
    """
    environ = os.environ if env is None else env

    # 1. GitHub Actions
    if environ.get("GITHUB_ACTIONS", "").lower() == "true":
        repo = environ.get("GITHUB_REPOSITORY")
        sha = environ.get("GITHUB_SHA")
        ref = environ.get("GITHUB_REF", "")
        ref_name = environ.get("GITHUB_REF_NAME")
        head_ref = environ.get("GITHUB_HEAD_REF")
        base_ref = environ.get("GITHUB_BASE_REF")
        event_name = environ.get("GITHUB_EVENT_NAME", "")

        pr_num = None
        if event_name == "pull_request" or "/pull/" in ref:
            # Extract PR number from ref if format is refs/pull/123/merge
            parts = ref.split("/")
            if len(parts) >= 3 and parts[1] == "pull":
                pr_num = parts[2]
            else:
                pr_num = head_ref or "PR"

        branch = head_ref if head_ref else (ref_name or ref)

        return CIEnvironment(
            is_ci=True,
            provider="github",
            repository=repo,
            branch=branch,
            commit_sha=sha,
            pull_request=pr_num,
            base_ref=base_ref,
            head_ref=head_ref,
        )

    # 2. GitLab CI
    if environ.get("GITLAB_CI", "").lower() == "true":
        return CIEnvironment(
            is_ci=True,
            provider="gitlab",
            repository=environ.get("CI_PROJECT_PATH"),
            branch=environ.get("CI_COMMIT_REF_NAME"),
            commit_sha=environ.get("CI_COMMIT_SHA"),
            pull_request=environ.get("CI_MERGE_REQUEST_IID"),
            base_ref=environ.get("CI_MERGE_REQUEST_TARGET_BRANCH_NAME"),
            head_ref=environ.get("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"),
        )

    # 3. CircleCI
    if environ.get("CIRCLECI", "").lower() == "true":
        user = environ.get("CIRCLE_PROJECT_USERNAME")
        repo = environ.get("CIRCLE_PROJECT_REPONAME")
        full_repo = f"{user}/{repo}" if user and repo else repo
        return CIEnvironment(
            is_ci=True,
            provider="circleci",
            repository=full_repo,
            branch=environ.get("CIRCLE_BRANCH"),
            commit_sha=environ.get("CIRCLE_SHA1"),
            pull_request=environ.get("CIRCLE_PULL_REQUEST") or environ.get("CIRCLE_PR_NUMBER"),
        )

    # 4. Jenkins
    if environ.get("JENKINS_URL") or environ.get("JENKINS_HOME") or (environ.get("BUILD_ID") and environ.get("EXECUTOR_NUMBER")):
        return CIEnvironment(
            is_ci=True,
            provider="jenkins",
            repository=environ.get("GIT_URL"),
            branch=environ.get("GIT_BRANCH"),
            commit_sha=environ.get("GIT_COMMIT"),
            pull_request=environ.get("CHANGE_ID"),
            base_ref=environ.get("CHANGE_TARGET"),
        )

    # 5. Azure Pipelines
    if environ.get("TF_BUILD", "").lower() == "true" or environ.get("AZURE_HTTP_USER_AGENT"):
        return CIEnvironment(
            is_ci=True,
            provider="azure",
            repository=environ.get("BUILD_REPOSITORY_NAME"),
            branch=environ.get("BUILD_SOURCEBRANCHNAME") or environ.get("BUILD_SOURCEBRANCH"),
            commit_sha=environ.get("BUILD_SOURCEVERSION"),
            pull_request=environ.get("SYSTEM_PULLREQUEST_PULLREQUESTID") or environ.get("SYSTEM_PULLREQUEST_PULLREQUESTNUMBER"),
            base_ref=environ.get("SYSTEM_PULLREQUEST_TARGETBRANCH"),
            head_ref=environ.get("SYSTEM_PULLREQUEST_SOURCEBRANCH"),
        )

    # 6. Generic CI
    ci_val = environ.get("CI", "").lower()
    continuous_integration = environ.get("CONTINUOUS_INTEGRATION", "").lower()
    if ci_val in ("true", "1") or continuous_integration in ("true", "1"):
        return CIEnvironment(
            is_ci=True,
            provider="generic",
            repository=environ.get("CI_REPO_NAME") or environ.get("REPOSITORY"),
            branch=environ.get("CI_BRANCH") or environ.get("BRANCH"),
            commit_sha=environ.get("CI_COMMIT") or environ.get("COMMIT_SHA"),
        )

    # 7. Local developer environment
    return CIEnvironment(
        is_ci=False,
        provider="local",
    )
