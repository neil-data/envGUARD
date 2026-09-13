"""Tests for CI environment detection module (envguard/ci.py)."""

from envguard.ci import CIEnvironment, detect_ci_environment


def test_detect_local_environment():
    """Verify local developer environment is detected when no CI env vars exist."""
    empty_env = {}
    ci_env = detect_ci_environment(empty_env)
    assert not ci_env.is_ci
    assert ci_env.provider == "local"
    assert ci_env.repository is None
    assert ci_env.commit_sha is None


def test_detect_github_actions():
    """Verify GitHub Actions environment detection and metadata extraction."""
    env = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "owner/repo",
        "GITHUB_SHA": "abc1234567890",
        "GITHUB_REF": "refs/pull/42/merge",
        "GITHUB_REF_NAME": "42/merge",
        "GITHUB_HEAD_REF": "feature-branch",
        "GITHUB_BASE_REF": "main",
        "GITHUB_EVENT_NAME": "pull_request",
    }
    ci_env = detect_ci_environment(env)
    assert ci_env.is_ci
    assert ci_env.provider == "github"
    assert ci_env.repository == "owner/repo"
    assert ci_env.commit_sha == "abc1234567890"
    assert ci_env.branch == "feature-branch"
    assert ci_env.pull_request == "42"
    assert ci_env.base_ref == "main"
    assert ci_env.head_ref == "feature-branch"


def test_detect_gitlab_ci():
    """Verify GitLab CI detection and metadata extraction."""
    env = {
        "GITLAB_CI": "true",
        "CI_PROJECT_PATH": "group/project",
        "CI_COMMIT_SHA": "fedcba987654",
        "CI_COMMIT_REF_NAME": "develop",
        "CI_MERGE_REQUEST_IID": "15",
        "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main",
        "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "develop",
    }
    ci_env = detect_ci_environment(env)
    assert ci_env.is_ci
    assert ci_env.provider == "gitlab"
    assert ci_env.repository == "group/project"
    assert ci_env.commit_sha == "fedcba987654"
    assert ci_env.branch == "develop"
    assert ci_env.pull_request == "15"
    assert ci_env.base_ref == "main"
    assert ci_env.head_ref == "develop"


def test_detect_circleci():
    """Verify CircleCI detection and metadata extraction."""
    env = {
        "CIRCLECI": "true",
        "CIRCLE_PROJECT_USERNAME": "acme",
        "CIRCLE_PROJECT_REPONAME": "app",
        "CIRCLE_SHA1": "112233445566",
        "CIRCLE_BRANCH": "patch-1",
        "CIRCLE_PULL_REQUEST": "https://github.com/acme/app/pull/99",
    }
    ci_env = detect_ci_environment(env)
    assert ci_env.is_ci
    assert ci_env.provider == "circleci"
    assert ci_env.repository == "acme/app"
    assert ci_env.commit_sha == "112233445566"
    assert ci_env.branch == "patch-1"
    assert ci_env.pull_request == "https://github.com/acme/app/pull/99"


def test_detect_jenkins():
    """Verify Jenkins environment detection."""
    env = {
        "JENKINS_URL": "http://jenkins.example.com/",
        "BUILD_ID": "100",
        "GIT_URL": "https://git.example.com/repo.git",
        "GIT_COMMIT": "aabbccddeeff",
        "GIT_BRANCH": "main",
    }
    ci_env = detect_ci_environment(env)
    assert ci_env.is_ci
    assert ci_env.provider == "jenkins"
    assert ci_env.repository == "https://git.example.com/repo.git"
    assert ci_env.commit_sha == "aabbccddeeff"
    assert ci_env.branch == "main"


def test_detect_azure_pipelines():
    """Verify Azure Pipelines detection."""
    env = {
        "TF_BUILD": "True",
        "BUILD_REPOSITORY_NAME": "org/repo",
        "BUILD_SOURCEVERSION": "998877665544",
        "BUILD_SOURCEBRANCHNAME": "main",
    }
    ci_env = detect_ci_environment(env)
    assert ci_env.is_ci
    assert ci_env.provider == "azure"
    assert ci_env.repository == "org/repo"
    assert ci_env.commit_sha == "998877665544"
    assert ci_env.branch == "main"


def test_detect_generic_ci():
    """Verify Generic CI detection via standard CI=true env var."""
    env = {
        "CI": "true",
        "CI_REPO_NAME": "custom/repo",
        "CI_COMMIT": "12345678",
        "CI_BRANCH": "release",
    }
    ci_env = detect_ci_environment(env)
    assert ci_env.is_ci
    assert ci_env.provider == "generic"
    assert ci_env.repository == "custom/repo"
    assert ci_env.commit_sha == "12345678"
    assert ci_env.branch == "release"


def test_safe_missing_vars_never_crashes():
    """Verify detector handles incomplete or empty environment dictionaries safely."""
    partial_env = {"GITHUB_ACTIONS": "true"}
    ci_env = detect_ci_environment(partial_env)
    assert ci_env.is_ci
    assert ci_env.provider == "github"
    assert ci_env.repository is None
    assert ci_env.commit_sha is None
