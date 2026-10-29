"""
Static review of a model-proposed Dockerfile patch.

Text checks only. No image is built and no container is run, so passing
this review does NOT mean the patch is secure or that it works. It only
catches problems that are visible in the Dockerfile text itself.
"""

import re
from typing import Any

# Accounts present in the Debian/Alpine bases used by official images.
# Any other named user must be created in the final stage.
BASE_IMAGE_USERS = {"root", "nobody", "daemon", "bin", "sys", "www-data"}

SECRET_KEY_RE = re.compile(r"(PASSWORD|PASSWD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)", re.IGNORECASE)
OVERCLAIM_RE = re.compile(r"^\s*#.*\b(fixed|verified|validated|tested|secured)\b", re.IGNORECASE)
CREATE_USER_RE = re.compile(r"\b(useradd|adduser)\b", re.IGNORECASE)
INSTRUCTION_RE = re.compile(r"^\s*([A-Za-z]+)\s+(.+)$")

DOCKERFILE_INSTRUCTIONS = (
    "FROM", "RUN", "CMD", "LABEL", "MAINTAINER", "EXPOSE", "ENV", "ADD", "COPY", "ENTRYPOINT",
    "VOLUME", "USER", "WORKDIR", "ARG", "ONBUILD", "STOPSIGNAL", "HEALTHCHECK", "SHELL",
)
# A literal backslash-n (text, not a line break) directly before an instruction or
# a comment line ("#"): the model escaped the line breaks, so several Dockerfile
# lines were joined into one.
ESCAPED_INSTRUCTION_BREAK_RE = re.compile(
    r"(?:\\r)?\\n(?=\s*(?:#|(?:" + "|".join(DOCKERFILE_INSTRUCTIONS) + r")\b))", re.IGNORECASE
)
# The USER name ends at whitespace or at a literal backslash-n, so text that a
# malformed patch glued on (e.g. "appuser\n# comment") is not read as the name.
_USER_TOKEN_END_RE = re.compile(r"\s|\\n")


def _user_token(value: str) -> str:
    return _USER_TOKEN_END_RE.split(value.strip(), maxsplit=1)[0]

NOTE = "Static text checks only. No image was built and no container was run."


def _instructions(text: str) -> list[tuple[str, str]]:
    joined = re.sub(r"\\\r?\n\s*", " ", text)
    result = []
    for line in joined.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        match = INSTRUCTION_RE.match(line)
        if match:
            result.append((match.group(1).upper(), match.group(2).strip()))
    return result


def _final_stage(instructions: list[tuple[str, str]]) -> list[tuple[str, str]]:
    starts = [i for i, (name, _) in enumerate(instructions) if name == "FROM"]
    return instructions[starts[-1]:] if starts else instructions


# Official Python Docker Hub image tags only. This is a version-support
# guardrail, not a registry lookup, an image vulnerability scan, or a build.
# As of 2026-10-30, Python 3.10 and earlier are end-of-life; 3.11+ are
# supported (https://devguide.python.org/versions/). Review as EOL dates advance.
MIN_SUPPORTED_PYTHON_SERIES = (3, 11)
OFFICIAL_PYTHON_IMAGE_NAMES = {
    "python", "library/python", "docker.io/library/python",
    "index.docker.io/library/python",
}
PYTHON_MINOR_TAG_RE = re.compile(r"^(\d+)\.(\d+)(?=$|[._-])")


def _python_base_issue(from_args: str) -> dict[str, str] | None:
    """Review an official Python FROM image, including --platform and build stages.

    An explicit version below the supported floor is rejected; an unversioned,
    variable or floating tag is marked unverified rather than falsely passing.
    Images from other publishers are not assumed to be official Python images.
    """
    parts = from_args.split()
    image = next((token for token in parts if not token.startswith("--")), "")
    image = image.split("@", 1)[0]
    repo, sep, tag = image.rpartition(":")
    if not sep:
        repo, tag = image, ""
    if repo.lower() not in OFFICIAL_PYTHON_IMAGE_NAMES:
        return None

    version = PYTHON_MINOR_TAG_RE.match(tag)
    if version:
        series = (int(version.group(1)), int(version.group(2)))
        if series < MIN_SUPPORTED_PYTHON_SERIES:
            return {
                "code": "unsupported_python_base",
                "message": (
                    f"Official Python image version {series[0]}.{series[1]} "
                    "is end-of-life as of October 2026; upgrade to a "
                    "supported series after testing application compatibility."
                ),
            }
        return None
    return {
        "code": "unverified_python_base_version",
        "message": (
            "The official Python base image has no verifiable major.minor version "
            "(for example 'latest', '3', or a variable tag); use a supported, "
            "explicit Python series and confirm compatibility."
        ),
    }


def _hardcoded_secrets(instructions: list[tuple[str, str]]) -> list[str]:
    found = []
    for name, value in instructions:
        if name not in ("ENV", "ARG"):
            continue
        pairs = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\"[^\"]*\"|'[^']*'|\S+)", value)
        if not pairs:  # legacy form: ENV KEY value
            parts = value.split(None, 1)
            if name == "ENV" and len(parts) == 2:
                pairs = [(parts[0], parts[1])]
        for key, raw in pairs:
            secret = raw.strip("\"'")
            if SECRET_KEY_RE.search(key) and secret and not secret.startswith("$"):
                found.append(key)
    return found


def _undefined_user(stage: list[tuple[str, str]]) -> str:
    users = [_user_token(value) for name, value in stage if name == "USER" and _user_token(value)]
    if not users:
        return ""
    user = users[-1].split(":")[0]
    if user.isdigit() or user.startswith("$") or user.lower() in BASE_IMAGE_USERS:
        return ""
    word = re.compile(rf"(?<![\w-]){re.escape(user)}(?![\w-])")
    created = any(
        name == "RUN" and CREATE_USER_RE.search(value) and word.search(value)
        for name, value in stage
    )
    return "" if created else user


def _final_user_issue(stage: list[tuple[str, str]]) -> dict[str, str] | None:
    """
    The container runs as the last USER of the final stage (root if there is none).
    Creating a user with useradd/adduser does not switch to it; only USER does.
    """
    users = [_user_token(value) for name, value in stage if name == "USER" and _user_token(value)]
    if not users:
        return {"code": "missing_user",
                "message": "No USER instruction in the final stage, so the container still runs as root "
                           "(creating a user with useradd/adduser does not switch to it)."}
    user = users[-1].split(":")[0]
    if user.lower() in ("root", "0"):
        return {"code": "root_user",
                "message": f"The final USER is '{users[-1]}', which is root."}
    if user.startswith("$"):
        return {"code": "unverified_user",
                "message": f"The final USER is a variable ('{users[-1]}'); a static check cannot "
                           f"confirm that it is not root."}
    return None


def review_patch(original: str, patched: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Return {"type": "static", "passed": bool, "issues": [{code, message}], "note": str}."""
    issues: list[dict[str, str]] = []
    if not patched.strip():
        return {"type": "static", "passed": True, "issues": [], "note": NOTE}

    # Escaped line breaks hide every instruction after the first, so no other
    # check below can be trusted for this text.
    if any(ESCAPED_INSTRUCTION_BREAK_RE.search(line) for line in patched.splitlines()) or re.search(r"\\n(?=\s*$)", patched, re.MULTILINE):
        issues.append({"code": "malformed_line_breaks",
                       "message": "Patch contains literal '\\n' sequences instead of line breaks, "
                                  "so it is not a valid multi-line Dockerfile."})

    # Reject unknown/garbled Dockerfile directives that could otherwise slip
    # through root/secret checks and be mislabeled a static PASS. This is still
    # a text-based check, not a full Dockerfile parser or a Docker build.
    joined = re.sub(r"\\\r?\n\s*", " ", patched)
    for line in joined.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = INSTRUCTION_RE.match(stripped)
        if not match:
            issues.append({"code": "malformed_instruction",
                           "message": "A Dockerfile line has no valid instruction and argument."})
        elif match.group(1).upper() not in DOCKERFILE_INSTRUCTIONS:
            issues.append({"code": "unknown_instruction",
                           "message": f"Unknown Dockerfile instruction '{match.group(1)}'."})

    instructions = _instructions(patched)
    # Check EVERY stage, not just the final stage, because old Python in a build
    # stage also remains part of the proposed Dockerfile.
    for instruction, arguments in instructions:
        if instruction == "FROM":
            image_issue = _python_base_issue(arguments)
            if image_issue:
                issues.append(image_issue)
    stage = _final_stage(instructions)

    for key in _hardcoded_secrets(instructions):
        issues.append({"code": "hardcoded_secret",
                       "message": f"Patch still hardcodes a secret in '{key}'."})

    user = _undefined_user(stage)
    if user:
        issues.append({"code": "undefined_user",
                       "message": f"USER '{user}' is never created in the final stage "
                                  f"(no useradd/adduser). Official python images do not define it, "
                                  f"so the container would fail to start."})

    user_issue = _final_user_issue(stage)
    if user_issue:
        issues.append(user_issue)

    patched_lines = {line.strip() for line in patched.splitlines() if line.strip()}
    original_lines = {line.strip() for line in original.splitlines() if line.strip()}
    for finding in findings:
        for line in str(finding.get("evidence", "")).splitlines():
            line = line.strip()
            if line and INSTRUCTION_RE.match(line) and line in original_lines and line in patched_lines:
                issues.append({"code": "unresolved_finding",
                               "message": f"{finding.get('id', '?')} ({finding.get('title') or finding.get('issue', '')}): "
                                          f"evidence line is unchanged in the patch: {line}"})

    for line in patched.splitlines():
        if OVERCLAIM_RE.match(line):
            issues.append({"code": "overclaim_comment",
                           "message": f"Patch comment claims a result that was not verified: {line.strip()}"})

    return {"type": "static", "passed": not issues, "issues": issues, "note": NOTE}
