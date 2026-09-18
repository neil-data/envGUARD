"""Shannon entropy detector with context validation and false-positive filtering."""

from collections import Counter
import math
import re
from typing import List, Optional, Tuple

from envguard.detectors.context_detector import (
    ASSIGNMENT_REGEX,
    CREDENTIAL_KEYWORDS,
    analyze_context,
)
from envguard.detectors.scoring import AdvancedDetectionConfig, DetectionCandidate
from envguard.utils import is_placeholder, mask_secret

UUID_REGEX = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
HEX_ONLY_REGEX = re.compile(r"^[0-9a-fA-F]+$")


def calculate_entropy(text: str) -> float:
    """Calculate the Shannon entropy of a string in bits per character.

    Returns 0.0 for empty or single-character strings.
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def is_uuid(value: str) -> bool:
    """Check if value matches standard UUID format (v1-v5)."""
    clean = value.strip().strip("'\"")
    return bool(UUID_REGEX.match(clean))


def is_generic_hash_or_commit(value: str) -> bool:
    """Check if value looks like a standalone git commit hash, checksum, or common hex digest."""
    val = value.strip().strip("'\"")
    # Git short hashes (7-12) or MD5 (32), SHA-1 (40), SHA-256 (64), SHA-512 (128)
    if len(val) in (7, 8, 10, 12, 32, 40, 64, 128) and HEX_ONLY_REGEX.match(val):
        return True
    return False


def is_code_expression(value: str) -> bool:
    """Check if value is a code expression (e.g. function call, environment lookup) rather than a literal secret."""
    clean = value.strip()
    if not clean:
        return False
    # Type hints / generic subscripts: e.g. Optional[...], List[...]
    if ("[" in clean and "]" in clean) or re.search(r"^(?:Optional|List|Dict|Tuple|Set|Union)\[", clean):
        return True
    # Attribute access / dotted identifier: e.g. config.disabled_rules, self.foo, a.b.c
    if re.search(r"^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_]", clean):
        return True
    # Check for known modules, functions, or runtime calls
    code_indicators = (
        "os.environ",
        "os.getenv",
        "environ.get",
        "process.env",
        "sys.",
        "re.compile",
        "config.get",
        "settings.get",
        "System.getenv",
        "getattr(",
        "lambda ",
        "${",
    )
    if any(ind in clean for ind in code_indicators):
        return True
    # Identifier immediately followed by '(' indicating a function or method invocation
    if re.search(r"[A-Za-z_][A-Za-z0-9_]*\s*\(", clean):
        return True
    # Unmatched trailing parenthesis or bracket from split expression
    if clean.endswith(")") or clean.endswith("]"):
        return True
    return False


def is_env_or_code_context(val: str, line: str) -> bool:
    """Check if a string literal appears inside an environment lookup or re.compile call."""
    if not line:
        return False
    escaped = re.escape(val)
    patterns = (
        r"""(?:os\.environ(?:\.get)?|os\.getenv|environ\.get|System\.getenv|process\.env)\s*[\(\[]\s*['"]""" + escaped + r"""['"]""",
        r"""re\.compile\s*\(\s*(?:r)?['"]""" + escaped + r"""['"]""",
        r"""(?:config|settings|request|params|args)\.get\s*\(\s*['"]""" + escaped + r"""['"]""",
    )
    for pat in patterns:
        if re.search(pat, line):
            return True
    return False


def is_regex_literal(value: str, line: str = "") -> bool:
    """Check if value represents a regular expression pattern rather than a credential."""
    clean = value.strip().strip("'\"")
    if not clean:
        return False

    # Check if prefixed with r' or r" in line
    if line:
        escaped = re.escape(value)
        if re.search(r"""r['"]""" + escaped + r"""['"]""", line):
            return True

    # Characteristic regex constructs and character classes
    regex_indicators = (
        r"[a-zA-Z",
        r"[0-9",
        r"[A-Z",
        r"[a-z",
        r"[A-Za-z",
        r"\d",
        r"\w",
        r"\s",
        r"\b",
        r"(?:",
        r"(?i)",
        r"(?m)",
        r"(?P<",
        r"(?=",
        r"(?!",
        r"(?<= ",
        r"(?<!",
        r"^[",
        r"]$",
    )
    if any(ind in clean for ind in regex_indicators):
        return True

    # Anchored patterns with regex meta characters
    if (clean.startswith("^") or clean.endswith("$")) and any(c in clean for c in "*+?{}[]()|\\"):
        return True

    return False


def is_alphabet_or_charset(val: str) -> bool:
    """Check if value represents an alphabet definition, character set, or base encoding table."""
    clean = val.strip().strip("'\"")
    if len(clean) < 16:
        return False

    # Never treat tokens with known provider prefixes as alphabets
    token_prefixes = (
        "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
        "sk_live_", "sk_test_", "pk_live_", "pk_test_", "whsec_",
        "AKIA", "ASIA", "xoxb-", "xoxp-", "xapp-", "sq0csp-", "sq0atp-",
        "glpat-", "npm_", "pypi-",
    )
    if any(clean.startswith(p) for p in token_prefixes):
        return False

    lower_clean = clean.lower()

    # 1. Base58 alphabet (length 58, 1-9 A-Z a-z excluding 0, O, I, l)
    base58_chars = "123456789abcdefghijkmnopqrstuvwxyz"
    if len(clean) >= 50 and sum(1 for c in lower_clean if c in base58_chars) >= len(clean) * 0.95:
        if len(set(clean)) >= 45:
            return True

    # 2. Base64 alphabet (A-Z a-z 0-9 + / or similar, length 64+)
    if len(clean) >= 64 and len(set(clean)) >= 60:
        if "abcdef" in lower_clean and "123456" in clean:
            return True

    # 3. Standard sequential alphabet (e.g. abcdefghijklmnopqrstuvwxyz)
    if "abcdefghijklm" in lower_clean:
        return True

    # 4. Standard sequential digits + alphabet (e.g. 0123456789...abcdef)
    if clean.startswith("0123456789") and len(set(clean)) >= 10:
        if "abcdef" in lower_clean or len(clean) >= 30:
            return True

    # 5. Full lowercase/uppercase character sets
    if clean in ("0123456789abcdef", "0123456789ABCDEF", "0123456789abcdefABCDEF"):
        return True

    return False


def is_windows_path(val: str) -> bool:
    """Check if value is a Windows filesystem path."""
    clean = val.strip().strip("'\"")
    if re.match(r"^[a-zA-Z]:[\\/]", clean):
        return True
    if clean.startswith(r"\\") or clean.startswith(r"\Users\\") or clean.startswith(r"\Program"):
        return True
    if "\\" in clean and any(term in clean.lower() for term in (
        ".exe", ".dll", ".sys", ".txt", ".json", ".py", ".log", ".bat", ".cmd", ".ps1",
        "users", "windows", "appdata", "temp", "program files", "system32"
    )):
        return True
    return False


def is_integrity_or_hash(val: str) -> bool:
    """Check if value is an SRI integrity hash or lockfile hash prefix."""
    clean = val.strip().strip("'\"")
    if any(clean.startswith(prefix) for prefix in ("sha512-", "sha384-", "sha256-", "sha1-", "md5-")):
        return True
    return False


def is_credential_variable(var_name: str) -> bool:
    """Check if a variable name suggests secret or credential storage."""
    clean = var_name.strip().lower()
    return any(keyword in clean for keyword in CREDENTIAL_KEYWORDS)


def _is_unquoted_code_syntax_or_literal(val: str) -> bool:
    """Check if an unquoted assignment value is code syntax, a numeric literal, or a language keyword."""
    clean = val.strip()
    if not clean:
        return True
    # Code punctuation that cannot appear in bare secret literals
    if any(char in clean for char in ("(", ")", "<", ">", "[", "]", "{", "}", ";", ",", "\\", "=", "+", "*")):
        return True
    # Member access or scope resolution
    if "::" in clean or "->" in clean:
        return True
    # Language keywords and boolean/null literals
    if clean.lower() in ("true", "false", "null", "undefined", "none", "nil", "nan", "infinity"):
        return True
    # Pure numeric literals
    if re.match(r"^-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$", clean):
        return True
    # Class or enum attribute access (e.g. EvasionClass.ENVIRONMENT_CHECK)
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z0-9_.]+$", clean):
        return True
    return False


def is_mime_type(val: str) -> bool:
    """Check if value is a standard MIME type or media type."""
    clean = val.strip().strip("'\"").lower()
    return bool(re.match(
        r"^(?:application|text|image|audio|video|font|multipart|model)/[a-zA-Z0-9.+_-]+$",
        clean,
    ))


def is_package_or_plugin(val: str) -> bool:
    """Check if value is an npm scoped package, framework plugin, or package identifier."""
    clean = val.strip().strip("'\"")
    if clean.startswith("@") and "/" in clean and re.match(r"^@[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+$", clean):
        return True
    if any(clean.startswith(prefix) for prefix in (
        "@vitejs/", "@babel/", "@types/", "@angular/", "@react/", "@next/", "@vue/", "@rollup/", "@webpack/"
    )):
        return True
    return False


def is_domain_or_url(val: str) -> bool:
    """Check if value is a network URL, domain name, or hostname."""
    clean = val.strip().strip("'\"").lower()
    if clean.startswith(("http://", "https://", "ftp://", "ssh://", "ws://", "wss://", "git://")):
        return True
    if "://" in clean or clean.startswith("//"):
        return True
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::[0-9]+)?(?:/.*)?$", clean):
        if "." in clean and not any(char in clean for char in ("=", "$", "#", "@")):
            return True
    return False


def is_css_declaration_string(val: str, line: str = "") -> bool:
    """Check if value is an inline CSS stylesheet rule or declaration block."""
    clean = val.strip().strip("'\"").lower()
    css_properties = (
        "font-family", "font-size", "font-weight", "color", "background", "margin",
        "margin-top", "margin-bottom", "margin-left", "margin-right",
        "padding", "padding-top", "padding-bottom", "border", "display", "position",
        "width", "height", "line-height", "z-index", "page-break", "box-shadow",
        "text-align", "justify-content", "align-items", "overflow", "flex",
    )
    if any(f"{prop}:" in clean or f"{prop} :" in clean for prop in css_properties):
        return True
    if clean.count(";") >= 1 and any(prop in clean for prop in css_properties):
        return True
    return False


def is_mock_or_test_placeholder(val: str) -> bool:
    """Check if value is an obvious test mock, sample, or placeholder."""
    clean = val.strip().strip("'\"")
    if clean.startswith('b"') or clean.startswith("b'"):
        clean = clean[2:].rstrip('"\'')
    lower = clean.lower()
    upper = clean.upper()
    if any(upper.startswith(p) for p in ("MOCK_", "TEST_", "DUMMY_", "SAMPLE_", "EXAMPLE_", "FAKE_")):
        return True
    if "_MOCK_" in upper:
        return True
    if lower in (
        "your_token", "your_api_key", "your_api_key_here", "your_secret",
        "my_secret", "sample_key", "your-api-key", "your-token-here",
    ) or any(phrase in lower for phrase in ("your_api_key", "your_secret_key", "insert_key_here", "replace_with_")):
        return True
    return False


def is_deterministic_hash_or_fingerprint(val: str) -> bool:
    """Check if value is a deterministic cryptographic hash, fingerprint, or digest."""
    clean = val.strip().strip("'\"")
    if re.match(r"^(?:sha256|sha512|sha384|sha1|md5|git|urn):[0-9a-fA-F]{32,128}$", clean, re.IGNORECASE):
        return True
    if re.match(r"^sha(?:256|384|512)-[A-Za-z0-9+/=]{40,100}$", clean):
        return True
    if is_uuid(clean):
        return True
    if re.match(r"^[0-9a-fA-F]{32}$", clean) or re.match(r"^[0-9a-fA-F]{40}$", clean) or re.match(r"^[0-9a-fA-F]{64}$", clean):
        return True
    return False


def is_code_identifier_or_constant(val: str) -> bool:
    """Check if value is a standard programming language identifier, API method, or class constant."""
    clean = val.strip().strip("'\"")
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$", clean):
        return True
    if clean.startswith("name=") or clean.startswith("android:name="):
        return True
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", clean):
        has_lower = any(c.islower() for c in clean)
        has_upper = any(c.isupper() for c in clean)
        if has_lower and has_upper and not any(c.isdigit() for c in clean):
            return True
        if clean.isupper() and "_" in clean:
            return True
        if "_" in clean and not any(c.isdigit() for c in clean) and clean.count("_") >= 2:
            return True
    return False


def extract_assignment_candidates(line: str) -> List[Tuple[str, str]]:
    """Extract variable name and assigned value pairs from a code or config line."""
    candidates: List[Tuple[str, str]] = []
    for match in ASSIGNMENT_REGEX.finditer(line):
        var_name = match.group(1).strip()
        is_quoted = match.group(3) is not None
        val = (match.group(3) if is_quoted else match.group(4) or "").strip().strip("'\"")
        if not val:
            continue
        # Unquoted values must NOT contain code syntax, booleans, or numbers
        if not is_quoted and _is_unquoted_code_syntax_or_literal(val):
            continue
        candidates.append((var_name, val))
    return candidates


def extract_literal_candidates(line: str) -> List[Tuple[str, str]]:
    """Extract assignment pairs and standalone quoted string literals from a line."""
    candidates: List[Tuple[str, str]] = []
    seen_values = set()

    # 1. Assignment pairs (var_name, val)
    for var_name, val in extract_assignment_candidates(line):
        clean_val = val.strip().strip("'\"")
        if clean_val and clean_val not in seen_values:
            candidates.append((var_name, clean_val))
            seen_values.add(clean_val)

    # 2. Standalone quoted string literals
    for match in re.finditer(r"""(?<![a-zA-Z0-9_])(['"])(.*?)\1""", line):
        clean_val = match.group(2).strip()
        if clean_val and clean_val not in seen_values:
            candidates.append(("", clean_val))
            seen_values.add(clean_val)

    return candidates


def is_android_permission_or_package(val: str) -> bool:
    """Check if value is an Android permission or Java/Android package identifier."""
    clean = val.strip().strip("'\"")
    if clean.startswith((
        "android.permission.",
        "com.android.",
        "android.intent.",
        "android.hardware.",
        "android.net.",
        "com.google.android.",
        "androidx.",
        "org.apache.",
    )):
        return True
    if re.match(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){2,}$", clean, re.IGNORECASE):
        return True
    return False


def is_css_property_or_style(val: str, line: str = "") -> bool:
    """Check if value is a CSS property, CSS variable, function, or style token."""
    clean = val.strip().strip("'\"")
    if clean.startswith("--") and re.match(r"^--[a-zA-Z0-9_-]+$", clean):
        return True
    if re.match(r"^(?:var|calc|rgb|rgba|hsl|hsla|linear-gradient|radial-gradient|url)\s*\(", clean):
        return True
    if re.match(r"^#[0-9a-fA-F]{3,8}$", clean):
        return True
    line_lower = line.lower()
    if any(k in line_lower for k in ("style", "css", "background", "color", "font", "border", "padding", "margin", "align", "justify")):
        if re.match(r"^[a-zA-Z0-9_-]+$", clean) and ("-" in clean or clean.lower() in ("sans-serif", "monospace", "border-box", "nowrap", "inline-block", "space-between")):
            return True
    return False


def is_shell_variable_or_flag(val: str) -> bool:
    """Check if value is a shell variable, parameter expansion, or command flag."""
    clean = val.strip().strip("'\"")
    if clean.startswith(("$", "${", "%")) or re.search(r"\$\{[A-Za-z0-9_]+\}", clean):
        return True
    if clean.startswith(("-", "--")):
        return True
    if ":" in clean and ("/" in clean or "\\" in clean):
        return True
    return False


def is_file_path_or_import(val: str) -> bool:
    """Check if value represents a filesystem path, import path, or file URI."""
    clean = val.strip().strip("'\"")
    if clean.startswith(("/", "./", "../", "~/", "@/")):
        return True
    if is_windows_path(clean):
        return True
    ext_pattern = r"\.(?:tsx?|jsx?|vue|html?|css|scss|sass|less|py|java|kt|c|cc|cpp|h|hpp|go|rs|rb|php|cs|swift|xml|json|ya?ml|toml|sql|sh|bash|md|svg|png|jpe?g|gif|ico|woff2?|ttf|eot|apk|aar|jar|tar|gz|zip|bin|so|dll|dylib)$"
    if ("/" in clean or "\\" in clean) and re.search(ext_pattern, clean, re.IGNORECASE):
        return True
    if clean.count("/") >= 2 or clean.count("\\") >= 2:
        return True
    return False


def is_code_identifier_or_function(val: str) -> bool:
    """Check if value is a standard programming language identifier (camelCase, PascalCase, snake_case)."""
    return is_code_identifier_or_constant(val)


def detect_entropy_candidates(
    line: str,
    line_number: int,
    file_path: str,
    config: AdvancedDetectionConfig,
) -> List[DetectionCandidate]:
    """Scan a line for high-entropy secret candidates using a context-first decision pipeline."""
    if not config.entropy_enabled:
        return []

    norm_path = file_path.replace("\\", "/").lower()
    file_name = norm_path.split("/")[-1]

    # Skip lockfiles and dependency metadata
    lockfiles = (
        "package-lock.json",
        "npm-shrinkwrap.json",
        "packages.lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pipfile.lock",
        "cargo.lock",
        "composer.lock",
        "gemfile.lock",
        "go.sum",
        "gradle.lockfile",
        "podfile.lock",
    )
    if file_name in lockfiles or file_name.endswith(".lock"):
        return []

    # Skip CSS / styling files
    if file_name.endswith((".css", ".scss", ".sass", ".less", ".styl", ".pcss")):
        return []

    # Skip documentation and markdown files
    if file_name.endswith((".md", ".rst", ".adoc", ".markdown", ".txt", ".doc", ".docx")) or any(part in norm_path for part in ("/docs/", "/doc/", "/documentation/", "/man/", "/wiki/")):
        return []

    # Skip YARA / static analysis rule files
    if file_name.endswith((".yar", ".yara", ".rules", ".ioc")) or any(part in norm_path for part in ("/yara/", "/rules/", "/signatures/")):
        return []

    # Skip test fixture and mock directories/files
    if any(part in norm_path for part in ("/fixtures/", "/testdata/", "/test_fixtures/", "/mocks/", "/stubs/", "/test-data/", "/samples/")) or file_name.endswith((".fixture", ".expected", ".snap", ".mock")):
        return []

    # Skip generated reports / audit artifacts / sarif
    if file_name.endswith((".sarif", ".sarif.json")) or file_name.startswith("envguard-") or any(term in file_name for term in ("audit", "report", "coverage", "benchmark", "summary", "trend", "result")):
        if file_name.endswith(".json") or file_name.endswith(".sarif"):
            return []

    stripped_line = line.strip()
    # Skip YARA rules syntax lines
    if stripped_line.startswith(("$", "rule ", "meta:", "strings:", "condition:")):
        return []

    candidates: List[DetectionCandidate] = []
    extracted = extract_literal_candidates(line)

    for var_name, val in extracted:
        # 1. Length check
        if len(val) < config.entropy_min_length:
            continue

        # 2. Secrets are discrete tokens; skip multi-word strings containing whitespace
        if any(c.isspace() for c in val):
            continue

        # 3. Skip URLs, anchors, schema references, file paths
        if val.startswith(("http://", "https://", "ftp://", "ssh://", "file://", "git://", "/", "./", "../", "#")):
            continue
        if "://" in val:
            continue

        # 4. Structural non-secret exclusions
        if is_mock_or_test_placeholder(val):
            continue
        if is_mime_type(val):
            continue
        if is_package_or_plugin(val):
            continue
        if is_domain_or_url(val):
            continue
        if is_css_declaration_string(val, line) or is_css_property_or_style(val, line):
            continue
        if is_android_permission_or_package(val):
            continue
        if is_shell_variable_or_flag(val):
            continue
        if is_file_path_or_import(val):
            continue
        if is_deterministic_hash_or_fingerprint(val):
            continue
        if is_code_identifier_or_constant(val):
            continue

        # 5. Skip dictionary / JSON object keys (e.g. "key": value)
        escaped_val = re.escape(val)
        if re.search(r"""['"]""" + escaped_val + r"""['"]\s*:""", line):
            continue

        # If candidate is a property in JSON/YAML, inspect property key for non-secret metadata
        key_match = re.search(r"""['"]?([A-Za-z0-9_.-]+)['"]?\s*:\s*['"]""" + escaped_val + r"""['"]""", line)
        if key_match:
            prop_key = key_match.group(1).lower()
            if prop_key in (
                "fingerprint", "hash", "digest", "guid", "ruleid", "ruleindex",
                "uri", "schema", "version", "title", "description", "message", "helpuri",
                "content-type", "content_type", "type", "format", "encoding",
            ):
                continue

        # 6. Skip format strings or template expressions
        if "{" in val or "}" in val or "%" in val:
            continue

        # 7. Skip placeholders immediately
        if is_placeholder(val):
            continue

        # 8. Skip code expressions (e.g. os.environ.get, os.getenv, method calls)
        if is_code_expression(val) or is_env_or_code_context(val, line):
            continue

        # 9. Skip regex literals
        if is_regex_literal(val, line):
            continue

        # 10. Skip UUIDs
        if is_uuid(val):
            continue

        # 11. Skip Windows paths
        if is_windows_path(val):
            continue

        # 12. Skip SRI and lockfile hashes
        if is_integrity_or_hash(val):
            continue

        # 13. Skip alphabet and character set definitions
        if is_alphabet_or_charset(val):
            continue

        # 14. Semantic Credential Context Decision:
        # Entropy alone is NEVER enough evidence.
        from envguard.detectors.context_detector import analyze_context, is_line_credential_context

        context_res = analyze_context(var_name, val) if var_name else None
        has_line_cred = is_line_credential_context(line)
        is_cred_var = bool(context_res and context_res.is_credential_context)
        is_non_secret = bool(context_res and context_res.is_non_secret_context)

        # Reject explicitly non-secret contexts immediately
        if is_non_secret:
            continue

        # Check symbol diversity: presence of special characters like !, @, #, $, %, ^, &, *
        special_symbols = set("!@#$%^&*~`|")
        symbol_count = sum(1 for c in val if c in special_symbols)
        has_high_symbol_diversity = symbol_count >= 2

        # Candidate must have positive credential context OR high symbol diversity in a variable assignment
        if not (is_cred_var or has_line_cred or (var_name and has_high_symbol_diversity)):
            continue

        # 15. Shannon entropy check
        entropy = calculate_entropy(val)
        if entropy < config.entropy_threshold:
            continue

        signals: List[str] = ["high_entropy", "token_like_length", "non_placeholder_value"]

        if is_cred_var:
            signals.append("credential_variable_name")
        elif has_line_cred:
            signals.append("credential_context")

        if has_high_symbol_diversity:
            signals.append("symbol_diversity_randomness")

        # Immediate masking and fingerprinting
        from envguard.scanner import compute_fingerprint
        fp = compute_fingerprint("generic-high-entropy-secret", file_path, val)
        masked = mask_secret(val)

        candidate = DetectionCandidate(
            value=val,
            var_name=var_name,
            line=line,
            line_number=line_number,
            file_path=file_path,
            source="entropy",
            signals=signals,
            entropy_value=entropy,
            rule_id="generic-high-entropy-secret",
            rule_name="High Entropy Secret",
            original_severity="MEDIUM",
            fingerprint=fp,
            masked_value=masked,
        )
        candidates.append(candidate)

    return candidates

    return candidates



def analyze_entropy_and_context(
    value: str,
    var_name: str = "",
    min_length: int = 16,
    entropy_threshold: float = 3.2,
) -> Tuple[bool, List[str]]:
    """Legacy backward-compatible analysis method."""
    val = value.strip().strip("'\"")
    signals: List[str] = []

    if len(val) < min_length:
        return False, signals

    if is_uuid(val):
        return False, ["UUID format (excluded)"]

    entropy = calculate_entropy(val)
    has_cred_name = is_credential_variable(var_name) if var_name else False
    if has_cred_name:
        signals.append(f"credential-like variable name ('{var_name}')")

    if len(val) >= min_length:
        signals.append(f"length threshold passed ({len(val)} chars)")

    if entropy >= entropy_threshold:
        signals.append(f"high entropy value ({entropy:.2f})")

    if is_generic_hash_or_commit(val) and not has_cred_name:
        return False, ["standalone hex hash / build id (excluded)"]

    is_suspicious = (entropy >= entropy_threshold) and (has_cred_name or len(val) >= 24)
    return is_suspicious, signals
