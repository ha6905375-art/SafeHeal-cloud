"""
Regression tests: a model returned the patched Dockerfile with escaped line breaks
(the text "\\n" instead of real newlines), so the whole file was a single line.

No network and no mock mode: a stub client object is passed to the service.
"""

import io
import json

import pytest
from fastapi.testclient import TestClient

from ai.config import Settings
from ai.patch_review import review_patch
from ai.response_parser import normalize_patch_line_breaks, parse_model_response
from ai.service import analyze_evidence
from backend import main

# Exact patched_dockerfile from the live Nemotron run (one line, 9 literal "\n").
LIVE_SINGLE_LINE_PATCH = (
    'FROM python:3.9-slim\\nENV AWS_SECRET_KEY=""\\nENV DEBUG_MODE="false"\\nWORKDIR /app'
    '\\nRUN useradd -m appuser\\nCOPY requirements.txt .\\nRUN pip install --no-cache-dir -r requirements.txt'
    '\\nCOPY . .\\nEXPOSE 5000\\nCMD ["python", "app.py"]'
)
LIVE_PATCH_LINES = [
    "FROM python:3.9-slim",
    'ENV AWS_SECRET_KEY=""',
    'ENV DEBUG_MODE="false"',
    "WORKDIR /app",
    "RUN useradd -m appuser",
    "COPY requirements.txt .",
    "RUN pip install --no-cache-dir -r requirements.txt",
    "COPY . .",
    "EXPOSE 5000",
    'CMD ["python", "app.py"]',
]
ORIGINAL = 'FROM python:3.9-slim\nENV DEBUG_MODE="true"\nWORKDIR /app\nEXPOSE 22\nCMD ["python", "app.py"]\n'
STUB_SETTINGS = Settings(
    mode="live", api_key="stub-key-not-used", base_url="https://example.invalid/v1", model="stub-model",
    timeout_seconds=5, max_retries=0, max_output_tokens=1024, json_mode="json_object",
)


class StubClient:
    """Returns one fixed reply; never touches the network."""

    def __init__(self, patched_dockerfile):
        self.content = json.dumps({
            "summary": "s",
            "findings": [{"id": "F-001", "title": "SSH port exposed", "severity": "HIGH",
                          "description": "d", "evidence": "EXPOSE 22", "recommendation": "r"}],
            "correlations": [],
            "patch": {"patched_dockerfile": patched_dockerfile, "diff": "", "summary": "p"},
            "limitations": [], "next_steps": [],
        })

    def chat(self, system_prompt, user_prompt):
        return {"content": self.content, "model": "stub-model", "usage": {}, "finish_reason": "stop"}


def analyze_with(patched, dockerfile=ORIGINAL):
    return analyze_evidence(dockerfile, None, settings=STUB_SETTINGS, client=StubClient(patched))


# ---------------- normalization ----------------

def test_live_single_line_patch_is_split_into_real_lines():
    fixed = normalize_patch_line_breaks(LIVE_SINGLE_LINE_PATCH)
    assert fixed.splitlines() == LIVE_PATCH_LINES
    assert "\\n" not in fixed


def test_escaped_newline_inside_a_command_is_kept():
    patch = 'FROM alpine\\nRUN printf "a\\nb" > /tmp/f\\nCMD ["cat", "/tmp/f"]'
    assert normalize_patch_line_breaks(patch).splitlines() == [
        "FROM alpine",
        'RUN printf "a\\nb" > /tmp/f',  # printf's own \n is not an instruction boundary
        'CMD ["cat", "/tmp/f"]',
    ]


def test_trailing_escaped_newline_becomes_a_real_one():
    assert normalize_patch_line_breaks("FROM alpine\\nUSER 1000\\n") == "FROM alpine\nUSER 1000\n"


@pytest.mark.parametrize("text", [
    "FROM python:3.11\n",                                    # valid one-instruction Dockerfile
    "FROM python:3.11",                                      # same, no trailing newline
    'FROM alpine\nRUN printf "a\\nb" > /tmp/f\n',            # valid multi-line with an escaped \n in a command
    "FROM alpine\\nUSER 1000\nCMD [\"sh\"]\n",              # mixed: has real line breaks, left for review
    "",
])
def test_valid_or_ambiguous_text_is_unchanged(text):
    assert normalize_patch_line_breaks(text) == text


def test_parser_normalizes_patch_and_warns():
    reply = json.dumps({"findings": [], "patch": {"patched_dockerfile": LIVE_SINGLE_LINE_PATCH}})
    parsed = parse_model_response(reply)
    assert parsed["patch"]["patched_dockerfile"].splitlines() == LIVE_PATCH_LINES
    assert any("literal '\\n'" in w for w in parsed["warnings"])


# ---------------- static patch review ----------------

@pytest.mark.parametrize("patch", [
    LIVE_SINGLE_LINE_PATCH,                                  # all on one line
    "FROM alpine\\nUSER 1000\nCMD [\"sh\"]\n",              # mixed: one line still joins two instructions
])
def test_review_rejects_escaped_line_breaks(patch):
    review = review_patch(ORIGINAL, patch, [])
    assert review["passed"] is False
    assert "malformed_line_breaks" in {i["code"] for i in review["issues"]}


@pytest.mark.parametrize("patch", [
    "FROM python:3.11\n",
    'FROM alpine\nRUN printf "a\\nb" > /tmp/f\nUSER 1000\n',
])
def test_real_line_breaks_are_not_flagged_as_malformed(patch):
    # Only the line-break rule is checked here; the USER rule is covered in test_patch_review_user.py.
    assert "malformed_line_breaks" not in {i["code"] for i in review_patch(ORIGINAL, patch, [])["issues"]}


# ---------------- through the AI service ----------------

def test_service_returns_normalized_patch_and_line_diff():
    result = analyze_with(LIVE_SINGLE_LINE_PATCH)
    assert result["status"] == "completed"
    assert result["patch"]["patched_dockerfile"].splitlines() == LIVE_PATCH_LINES
    assert "+RUN useradd -m appuser\n" in result["patch"]["diff"]  # a real per-line diff
    codes = {i["code"] for i in result["ai"]["patch_review"]["issues"]}
    assert "malformed_line_breaks" not in codes
    assert any("literal '\\n'" in w for w in result["ai"]["warnings"])


def test_secret_in_single_line_patch_is_still_redacted():
    secret = "supersecretvalue123"
    result = analyze_with(f"FROM python:3.11-slim\\nENV API_KEY={secret}\\nUSER 1000")
    assert secret not in json.dumps(result)
    assert "ENV API_KEY=[REDACTED]" in result["patch"]["patched_dockerfile"].splitlines()
    assert "hardcoded_secret" in {i["code"] for i in result["ai"]["patch_review"]["issues"]}


# ---------------- through the backend endpoint ----------------

def test_backend_reviews_the_real_lines_of_the_patch(monkeypatch):
    def analyze(docker_text, logs):
        return analyze_evidence(docker_text, logs, settings=STUB_SETTINGS, client=StubClient(LIVE_SINGLE_LINE_PATCH))

    monkeypatch.setattr(main, "analyze_evidence", analyze)
    response = TestClient(main.app).post("/api/analyze", files={
        "dockerfile": ("Dockerfile", io.BytesIO(ORIGINAL.encode()), "text/plain"),
    })
    assert response.status_code == 200
    data = response.json()
    assert data["patch"]["patched_dockerfile"].splitlines() == LIVE_PATCH_LINES
    # The live patch adds a user but never switches to it; the backend now sees that on real lines.
    assert data["tests"]["proposed_patch"]["passed"] is False
    assert "Missing non-root USER instruction" in data["tests"]["proposed_patch"]["details"]
    assert data["ai"]["patch_status"] == "proposed_failed_static_review"


# ---------------- comments next to escaped line breaks ----------------
# Regression: the reviewer reported USER 'appuser\n#' because a literal "\n" before a
# comment line was not treated as a line break, so the comment stayed glued to USER.

COMMENTED_LINES = [
    "FROM python:3.11-slim",
    "# Create an unprivileged user",
    "RUN useradd -m appuser",
    "# Switch to the non-root user",
    "USER appuser",
    "# Expose the app port",
    "EXPOSE 5000",
    'CMD ["python", "app.py"]',
]
COMMENTED_SINGLE_LINE = "\\n".join(COMMENTED_LINES)
# Shape of the failing live case: only the USER line is followed by a comment.
USER_THEN_COMMENT = (
    "FROM python:3.11-slim\\nRUN useradd -m appuser\\nUSER appuser\\n# Expose the app port"
    '\\nEXPOSE 5000\\nCMD ["python", "app.py"]'
)
# Real line breaks, but the USER line still has an escaped break before a comment.
MIXED = "\n".join(COMMENTED_LINES[:4] + ["USER appuser\\n# Expose the app port"] + COMMENTED_LINES[6:]) + "\n"


@pytest.mark.parametrize("raw", [COMMENTED_SINGLE_LINE, USER_THEN_COMMENT])
def test_escaped_break_before_comment_becomes_a_real_line_break(raw):
    lines = normalize_patch_line_breaks(raw).splitlines()
    assert "USER appuser" in lines
    assert not any("\\n" in line for line in lines)
    if raw is COMMENTED_SINGLE_LINE:
        assert lines == COMMENTED_LINES


@pytest.mark.parametrize("raw", [COMMENTED_SINGLE_LINE, USER_THEN_COMMENT])
def test_commented_patch_with_useradd_and_user_passes_after_parsing(raw):
    # Before the fix, COMMENTED_SINGLE_LINE also "passed" here, but for the wrong reason: the
    # partially normalized text kept "appuser\n#" glued in both the RUN and USER lines, so the
    # garbage token looked created. Check the real lines, not just the verdict.
    parsed = parse_model_response(json.dumps({"findings": [], "patch": {"patched_dockerfile": raw}}))
    patched = parsed["patch"]["patched_dockerfile"]
    assert "USER appuser" in patched.splitlines()
    assert "\\n" not in patched
    review = review_patch(ORIGINAL, patched, [])
    assert review["passed"] is True, review["issues"]  # appuser is created and switched to


def test_real_multiline_dockerfile_with_adjacent_comments_passes():
    review = review_patch(ORIGINAL, "\n".join(COMMENTED_LINES) + "\n", [])
    assert review["passed"] is True and review["issues"] == []


@pytest.mark.parametrize("raw", [COMMENTED_SINGLE_LINE, USER_THEN_COMMENT, MIXED])
def test_unnormalized_text_with_escaped_comment_breaks_is_rejected(raw):
    # Text that is not normalized must be rejected as malformed. Before the fix the mixed
    # text was rejected only with a misleading undefined_user for "appuser\n#".
    codes = {i["code"] for i in review_patch(ORIGINAL, raw, [])["issues"]}
    assert "malformed_line_breaks" in codes
    assert "undefined_user" not in codes  # the user name is read as "appuser", not "appuser\n#"


def test_mixed_text_is_left_unchanged_by_normalization():
    # Text with real line breaks is never rewritten; the review rejects it instead.
    assert normalize_patch_line_breaks(MIXED) == MIXED


def test_hash_inside_a_command_is_not_split():
    patch = 'FROM alpine\\nRUN echo "build #42" > /tmp/v\\nUSER 1000'
    assert normalize_patch_line_breaks(patch).splitlines() == [
        "FROM alpine", 'RUN echo "build #42" > /tmp/v', "USER 1000",
    ]


def test_service_accepts_the_commented_patch_as_proposed_not_validated():
    result = analyze_with(COMMENTED_SINGLE_LINE)
    assert result["status"] == "completed"
    assert result["patch"]["patched_dockerfile"].splitlines() == COMMENTED_LINES
    assert result["ai"]["patch_review"]["passed"] is True
    assert result["ai"]["patch_status"] == "proposed_not_validated"  # static only, never "validated"
