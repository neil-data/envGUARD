"""Remediation engine for EnvGuard v0.8.0.

Provides safe, local-first code transformations and environment synchronization:
- Rewrites hardcoded Python assignments to `os.environ.get("KEY")`.
- Safely injects `import os` if not already present.
- Syncs `.env` (with secret) and `.env.example` (strictly with placeholder!).
- Refuses unsafe, multiline, or ambiguous constructs.
- Supports atomic file writes with zero partial write states.
"""

import ast
from dataclasses import dataclass, field
import difflib
import os
from pathlib import Path
import re
import shutil
import tempfile
from typing import Dict, List, Optional, Set, Tuple

from envguard.git_utils import is_git_repository, run_git
from envguard.scanner import ScanFinding
from envguard.secrets_manager import detect_secrets_manager_reference


@dataclass
class RemediationAction:
    file_path: Path
    line_number: int
    rule_id: str
    rule_name: str
    original_line: str
    replacement_line: str
    env_var_name: str
    raw_secret: str
    masked_secret: str
    is_safe: bool = True
    skip_reason: Optional[str] = None
    diff: str = ""
    needs_import_os: bool = False


@dataclass
class RemediationPlan:
    target_root: Path
    actions: List[RemediationAction] = field(default_factory=list)
    env_additions: Dict[str, str] = field(default_factory=dict)         # KEY -> raw_secret
    example_additions: Dict[str, str] = field(default_factory=dict)     # KEY -> placeholder
    skipped_secrets_manager: List[Tuple[ScanFinding, str]] = field(default_factory=list)
    needs_gitignore_env: bool = False

    @property
    def safe_actions(self) -> List[RemediationAction]:
        return [a for a in self.actions if a.is_safe]

    @property
    def manual_actions(self) -> List[RemediationAction]:
        return [a for a in self.actions if not a.is_safe]

    @property
    def affected_files(self) -> Set[Path]:
        return {a.file_path for a in self.safe_actions}


def normalize_env_var_name(var_name: str, rule_id: str) -> str:
    """Derive a clean, uppercase environment variable key name."""
    clean_name = re.sub(r"[^a-zA-Z0-9_]", "_", var_name).upper().strip("_")
    if clean_name and not clean_name.isdigit():
        return clean_name

    # Fallback to rule id based name
    rule_clean = re.sub(r"[^a-zA-Z0-9_]", "_", rule_id).upper().strip("_")
    return rule_clean or "SECRET_KEY"


def is_env_ignored_by_git(target_root: Path) -> bool:
    """Check if .env is ignored by git in target_root or via .gitignore."""
    if is_git_repository(target_root):
        proc = run_git(["check-ignore", "-q", ".env"], cwd=target_root)
        if proc.returncode == 0:
            return True

    # Check local .gitignore file
    gitignore_path = target_root / ".gitignore"
    if gitignore_path.is_file():
        try:
            content = gitignore_path.read_text(encoding="utf-8-sig", errors="replace")
            for line in content.splitlines():
                stripped = line.strip()
                if stripped in (".env", "/.env", ".env*", "*.env"):
                    return True
        except Exception:
            pass

    return False


def ensure_env_in_gitignore(target_root: Path, backups: Optional[Dict[Path, Optional[bytes]]] = None) -> bool:
    """Ensure .gitignore exists and excludes .env. Returns True if modified/created."""
    if is_env_ignored_by_git(target_root):
        return False

    gitignore_path = target_root / ".gitignore"
    if backups is not None and gitignore_path not in backups:
        backups[gitignore_path] = gitignore_path.read_bytes() if gitignore_path.is_file() else None

    lines_to_add = [
        "",
        "# Environment files (added by envguard fix)",
        ".env",
        ".env.local",
        ".env.*.local",
    ]
    if gitignore_path.is_file():
        existing = gitignore_path.read_text(encoding="utf-8-sig", errors="replace")
        prefix = "" if not existing or existing.endswith("\n") else "\n"
        new_content = existing + prefix + "\n".join(lines_to_add).lstrip("\n") + "\n"
    else:
        new_content = "\n".join(lines_to_add).lstrip("\n") + "\n"

    gitignore_path.write_text(new_content, encoding="utf-8")
    return True


def inspect_python_assignment(file_path: Path, line_number: int, raw_secret: str) -> Tuple[bool, Optional[str], Optional[str], bool]:
    """Parse Python file using AST to verify if target is a simple, safe assignment.

    Returns:
        (is_safe, var_name, skip_reason, needs_import_os)
    """
    try:
        content = file_path.read_text(encoding="utf-8-sig", errors="replace")
        tree = ast.parse(content, filename=str(file_path))
    except Exception as e:
        return False, None, f"Failed to parse Python syntax: {e}", False

    # Check if 'os' module is imported
    has_os_import = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "os":
                    has_os_import = True
                    break
        elif isinstance(node, ast.ImportFrom):
            if node.module == "os":
                has_os_import = True

    needs_import_os = not has_os_import

    # Find assignment node corresponding to line_number
    target_node = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            if getattr(node, "lineno", None) == line_number:
                target_node = node
                break

    if not target_node:
        return False, None, "Target finding is not a direct variable assignment statement; manual remediation required.", needs_import_os

    # Check assignment value
    val_node = target_node.value if isinstance(target_node, (ast.Assign, ast.AnnAssign)) else None
    if val_node is None:
        return False, None, "Assignment has no value expression; manual remediation required.", needs_import_os

    # Only support simple string constants: VAR = "secret"
    if not isinstance(val_node, ast.Constant) or not isinstance(val_node.value, str):
        return False, None, "Value is not a single string literal (e.g. f-string, multiline concatenation, or function call); manual remediation required.", needs_import_os

    if val_node.value != raw_secret:
        # If the literal doesn't match the raw secret exactly
        if raw_secret not in val_node.value:
            return False, None, "Secret is embedded in a complex string; manual remediation required.", needs_import_os

    # Extract target variable name
    var_name = None
    if isinstance(target_node, ast.Assign):
        if len(target_node.targets) == 1 and isinstance(target_node.targets[0], ast.Name):
            var_name = target_node.targets[0].id
        else:
            return False, None, "Multiple or non-identifier assignment target; manual remediation required.", needs_import_os
    elif isinstance(target_node, ast.AnnAssign):
        if isinstance(target_node.target, ast.Name):
            var_name = target_node.target.id
        else:
            return False, None, "Annotated target is not a simple identifier; manual remediation required.", needs_import_os

    return True, var_name, None, needs_import_os


def generate_diff(original: str, modified: str, filename: str) -> str:
    """Generate unified diff string between original and modified content."""
    orig_lines = original.splitlines(keepends=True)
    mod_lines = modified.splitlines(keepends=True)
    diff = difflib.unified_diff(
        orig_lines,
        mod_lines,
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
        lineterm="",
    )
    return "".join(diff)


def create_remediation_plan(
    target_root: Path,
    findings: List[ScanFinding],
) -> RemediationPlan:
    """Analyze findings and build a comprehensive RemediationPlan."""
    plan = RemediationPlan(target_root=target_root)

    for f in findings:
        file_path = (target_root / f.file_path).resolve()
        if not file_path.is_file():
            continue

        file_name = file_path.name.lower()
        # .env and .env.example are environment stores, never remediated as source code
        if file_name == ".env" or file_name.startswith(".env.") or file_name.endswith(".env"):
            continue

        # Check for Secrets Manager pattern
        sec_mgr = detect_secrets_manager_reference(f.line_snippet)
        if sec_mgr:
            plan.skipped_secrets_manager.append((f, sec_mgr[1]))
            continue

        # Check file extension: python only in v0.8.x
        suffix = file_path.suffix.lower()
        is_python = (suffix == ".py")

        if not is_python:
            plan.actions.append(
                RemediationAction(
                    file_path=file_path,
                    line_number=f.line_number,
                    rule_id=f.rule_id,
                    rule_name=f.rule_name,
                    original_line=f.line_snippet,
                    replacement_line="",
                    env_var_name="",
                    raw_secret=f.raw_value,
                    masked_secret=f.masked_value,
                    is_safe=False,
                    skip_reason=f"File type '{suffix or file_name}' is not supported for automatic remediation in v0.8.x.",
                )
            )
            continue

        is_safe, var_name, skip_reason, needs_import_os = inspect_python_assignment(
            file_path=file_path,
            line_number=f.line_number,
            raw_secret=f.raw_value,
        )

        if not is_safe or not var_name:
            plan.actions.append(
                RemediationAction(
                    file_path=file_path,
                    line_number=f.line_number,
                    rule_id=f.rule_id,
                    rule_name=f.rule_name,
                    original_line=f.line_snippet,
                    replacement_line="",
                    env_var_name="",
                    raw_secret=f.raw_value,
                    masked_secret=f.masked_value,
                    is_safe=False,
                    skip_reason=skip_reason or "Unsafe assignment construct",
                )
            )
            continue

        env_key = normalize_env_var_name(var_name, f.rule_id)
        # Strip any leading BOM from line snippet to avoid corrupting indentation/syntax
        orig_line = f.line_snippet.lstrip("\ufeff").rstrip("\r\n")

        # Determine indentation
        indent_match = re.match(r"^(\s*)", orig_line)
        indent = indent_match.group(1) if indent_match else ""

        # Preserve variable name and assignment syntax
        replacement_line = f'{indent}{var_name} = os.environ.get("{env_key}")'

        action = RemediationAction(
            file_path=file_path,
            line_number=f.line_number,
            rule_id=f.rule_id,
            rule_name=f.rule_name,
            original_line=orig_line,
            replacement_line=replacement_line,
            env_var_name=env_key,
            raw_secret=f.raw_value,
            masked_secret=f.masked_value,
            is_safe=True,
            needs_import_os=needs_import_os,
        )
        action.diff = generate_diff(orig_line + "\n", replacement_line + "\n", file_path.name)
        plan.actions.append(action)

        # Record .env and .env.example additions
        plan.env_additions[env_key] = f.raw_value
        # STRICT REQUIREMENT: Never write raw_value to .env.example
        plan.example_additions[env_key] = "your-secret-key-here"

    if plan.env_additions and not is_env_ignored_by_git(target_root):
        plan.needs_gitignore_env = True

    return plan


def check_git_cleanliness(target_dir: Path) -> Tuple[bool, str]:
    """Verify that Git working tree has no uncommitted changes."""
    if not is_git_repository(target_dir):
        return True, ""  # Not a git repo, skip check

    proc = run_git(["status", "--porcelain"], cwd=target_dir)
    if proc.returncode != 0:
        return False, "Failed to inspect Git status."

    changes = proc.stdout.decode("utf-8", errors="replace").strip()
    if changes:
        return False, "Git working tree contains uncommitted or unstaged changes. Commit or stash them before running 'envguard fix --apply', or use --allow-dirty."

    return True, ""


def apply_remediation_plan(plan: RemediationPlan) -> None:
    """Atomically apply all safe actions in the remediation plan with backup recovery.

    Raises:
        RuntimeError if validation or writing fails, cleanly restoring all modified files.
    """
    if not plan.safe_actions and not plan.env_additions and not plan.example_additions:
        return

    backups: Dict[Path, Optional[bytes]] = {}
    staged_files: List[Path] = []

    try:
        # Step 1: Backup all targets in memory (raw bytes for exact bit-for-bit fidelity)
        files_to_touch = plan.affected_files.copy()
        env_file = plan.target_root / ".env"
        example_file = plan.target_root / ".env.example"
        gitignore_file = plan.target_root / ".gitignore"

        if plan.env_additions:
            files_to_touch.add(env_file)
            if not is_env_ignored_by_git(plan.target_root):
                files_to_touch.add(gitignore_file)
        if plan.example_additions:
            files_to_touch.add(example_file)

        for p in files_to_touch:
            backups[p] = p.read_bytes() if p.is_file() else None

        # Step 2: Prepare new content for source files
        actions_by_file: Dict[Path, List[RemediationAction]] = {}
        for a in plan.safe_actions:
            actions_by_file.setdefault(a.file_path, []).append(a)

        for file_path, actions in actions_by_file.items():
            if file_path.suffix.lower() == ".py":
                raw_bytes = backups.get(file_path)
                if raw_bytes is None:
                    raw_bytes = file_path.read_bytes() if file_path.is_file() else b""
                has_bom = raw_bytes.startswith(b"\xef\xbb\xbf")
                orig_content = raw_bytes.decode("utf-8-sig", errors="replace")
                orig_lines = orig_content.splitlines(keepends=True)

                # Line replacement (1-based index)
                # Sort actions in reverse line order to prevent line shift issues
                sorted_actions = sorted(actions, key=lambda x: x.line_number, reverse=True)
                for act in sorted_actions:
                    idx = act.line_number - 1
                    if 0 <= idx < len(orig_lines):
                        newline = orig_lines[idx].endswith("\r\n") and "\r\n" or "\n"
                        orig_lines[idx] = act.replacement_line.rstrip("\r\n") + newline

                modified_content = "".join(orig_lines)

                # Inject import os if needed
                needs_os = any(a.needs_import_os for a in actions)
                if needs_os:
                    # Check if 'import os' is in modified_content
                    parsed = ast.parse(modified_content)
                    has_os = any(
                        (isinstance(n, ast.Import) and any(alias.name == "os" for alias in n.names)) or
                        (isinstance(n, ast.ImportFrom) and n.module == "os")
                        for n in ast.walk(parsed)
                    )
                    if not has_os:
                        # Find appropriate insertion point: after docstring or at top
                        lines = modified_content.splitlines(keepends=True)
                        insert_idx = 0
                        for i, line in enumerate(lines):
                            stripped = line.strip()
                            if stripped.startswith('"""') or stripped.startswith("'''"):
                                # Skip docstring
                                for j in range(i + 1, len(lines)):
                                    if '"""' in lines[j] or "'''" in lines[j]:
                                        insert_idx = j + 1
                                        break
                                break
                            elif stripped and not stripped.startswith("#"):
                                insert_idx = i
                                break

                        lines.insert(insert_idx, "import os\n")
                        modified_content = "".join(lines)

                # Post-write syntax validation: must compile cleanly without BOM
                ast.parse(modified_content, filename=str(file_path))

                # Write to temp file in same directory for atomic replace
                temp_fd, temp_path_str = tempfile.mkstemp(dir=file_path.parent, prefix="envguard_fix_")
                os.close(temp_fd)
                temp_path = Path(temp_path_str)
                staged_files.append(temp_path)

                # Preserve BOM if original had BOM
                if has_bom:
                    temp_path.write_bytes(b"\xef\xbb\xbf" + modified_content.encode("utf-8"))
                else:
                    temp_path.write_text(modified_content, encoding="utf-8")

                os.replace(temp_path, file_path)

        # Step 3: Update .env safely (never overwrite existing keys)
        if plan.env_additions:
            env_bytes = backups.get(env_file)
            env_content = env_bytes.decode("utf-8-sig", errors="replace") if env_bytes else ""
            existing_keys = set()
            for line in env_content.splitlines():
                m = re.match(r"^\s*(?:export\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*=", line)
                if m:
                    existing_keys.add(m.group(1))

            new_env_lines = []
            for k, val in plan.env_additions.items():
                if k not in existing_keys:
                    new_env_lines.append(f'{k}="{val}"')

            if new_env_lines:
                append_text = "\n" + "\n".join(new_env_lines) + "\n" if env_content and not env_content.endswith("\n") else "\n".join(new_env_lines) + "\n"
                final_env = env_content + append_text if env_content else "".join(new_env_lines) + "\n"

                temp_fd, temp_path_str = tempfile.mkstemp(dir=plan.target_root, prefix=".env_tmp_")
                os.close(temp_fd)
                temp_path = Path(temp_path_str)
                staged_files.append(temp_path)
                temp_path.write_text(final_env, encoding="utf-8")
                os.replace(temp_path, env_file)

        # Step 4: Update .env.example strictly with placeholder (never real secret!)
        if plan.example_additions:
            ex_bytes = backups.get(example_file)
            ex_content = ex_bytes.decode("utf-8-sig", errors="replace") if ex_bytes else ""
            existing_keys = set()
            for line in ex_content.splitlines():
                m = re.match(r"^\s*(?:export\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*=", line)
                if m:
                    existing_keys.add(m.group(1))

            new_ex_lines = []
            for k, placeholder in plan.example_additions.items():
                if k not in existing_keys:
                    # STRICT SECURITY ASSERTION: Must never equal raw secret
                    assert placeholder != plan.env_additions.get(k), "CRITICAL: Plaintext secret leak prevented in .env.example generator!"
                    new_ex_lines.append(f'{k}="{placeholder}"')

            if new_ex_lines:
                append_text = "\n" + "\n".join(new_ex_lines) + "\n" if ex_content and not ex_content.endswith("\n") else "\n".join(new_ex_lines) + "\n"
                final_ex = ex_content + append_text if ex_content else "".join(new_ex_lines) + "\n"

                temp_fd, temp_path_str = tempfile.mkstemp(dir=plan.target_root, prefix=".example_tmp_")
                os.close(temp_fd)
                temp_path = Path(temp_path_str)
                staged_files.append(temp_path)
                temp_path.write_text(final_ex, encoding="utf-8")
                os.replace(temp_path, example_file)

        # Step 5: Ensure .gitignore excludes .env when secrets are extracted
        if plan.env_additions:
            ensure_env_in_gitignore(plan.target_root, backups)

    except Exception as e:
        # Atomic rollback on any failure
        for p, original_bytes in backups.items():
            try:
                if original_bytes is None:
                    if p.exists():
                        p.unlink()
                else:
                    p.write_bytes(original_bytes)
            except Exception:
                pass

        # Cleanup dangling temporary files
        for tmp in staged_files:
            if tmp.exists():
                try:
                    tmp.unlink()
                except Exception:
                    pass

        raise RuntimeError(f"Remediation failed during write validation: {e}. All files rolled back safely.")
