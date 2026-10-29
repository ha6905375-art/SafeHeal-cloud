
"""Regression tests for Nemotron Dockerfile patch formatting."""

from ai.prompts import SYSTEM_PROMPT
from ai.patch_review import review_patch
from ai.response_parser import normalize_patch_line_breaks


def test_prompt_requires_real_decoded_dockerfile_line_breaks():
    assert "patch.patched_dockerfile" in SYSTEM_PROMPT
    assert "REAL newline" in SYSTEM_PROMPT
    assert "double-escape" in SYSTEM_PROMPT
    assert "one instruction per line" in SYSTEM_PROMPT


def test_mixed_redundant_breaks_are_cleaned():
    original = (
        'FROM python:3.11-slim\n'
        'EXPOSE 22\n'
        'CMD ["python", "app.py"]\n'
    )

    malformed = (
        'FROM python:3.11-slim\\n\n'
        'RUN useradd -m appuser\\n\n'
        'USER appuser\\n\n'
        'EXPOSE 5000\n'
        'CMD ["python", "app.py"]'
    )

    fixed = normalize_patch_line_breaks(malformed)

    assert "\\n" not in fixed
    assert "USER appuser" in fixed.splitlines()

    result = review_patch(original, fixed, [])
    assert result["passed"] is True


def test_ambiguous_escaped_break_is_not_silently_accepted():
    original = 'FROM alpine\nEXPOSE 22\n'

    malformed = (
        'FROM alpine\n'
        'USER 1000\\nEXPOSE 5000\n'
    )

    fixed = normalize_patch_line_breaks(malformed)

    assert fixed == malformed

    result = review_patch(original, fixed, [])
    assert result["passed"] is False


def test_printf_escape_with_real_line_break_is_preserved():
    patch = (
        'FROM alpine\n'
        'RUN printf "a\\nb" > /tmp/f\n'
        'USER 1000\n'
    )

    assert normalize_patch_line_breaks(patch) == patch


def test_live_patch_with_malformed_user_is_rejected():
    original = 'FROM python:3.11-slim\nEXPOSE 22\n'

    malformed = (
        'FROM python:3.11-slim\\n\n'
        'WORKDIR /app\\n\n'
        'RUN useradd -m appuser\n'
        'USERappuser\\n\n'
        'COPY . .\\n\n'
        'EXPOSE 5000\\n\n'
        'CMD ["python", "app.py"]'
    )

    fixed = normalize_patch_line_breaks(malformed)

    result = review_patch(original, fixed, [])

    print("PATCH REVIEW ISSUES:", result["issues"])

    assert result["passed"] is False
    assert len(result["issues"]) > 0



def test_nebius_patch_missing_user_is_rejected():
    """Regression test for the actual Nebius patch failure."""
    original = (
        'FROM python:3.11-slim\n'
        'EXPOSE 22\n'
        'CMD ["python", "app.py"]\n'
    )

    # AI created the user but forgot to switch to it.
    bad_patch = (
        'FROM python:3.11-slim\n'
        'WORKDIR /app\n'
        'RUN useradd -m appuser\n'
        'COPY . .\n'
        'EXPOSE 5000\n'
        'CMD ["python", "app.py"]\n'
    )

    result = review_patch(original, bad_patch, [])

    assert result["passed"] is False
    assert any(
        issue["code"] == "missing_user"
        for issue in result["issues"]
    )


def test_nebius_patch_with_nonroot_user_passes():
    """Verify that adding USER appuser fixes the reported issue."""
    original = (
        'FROM python:3.11-slim\n'
        'EXPOSE 22\n'
        'CMD ["python", "app.py"]\n'
    )

    good_patch = (
        'FROM python:3.11-slim\n'
        'WORKDIR /app\n'
        'RUN useradd -m appuser\n'
        'COPY . .\n'
        'EXPOSE 5000\n'
        'USER appuser\n'
        'CMD ["python", "app.py"]\n'
    )

    result = review_patch(original, good_patch, [])

    assert result["passed"] is True


def test_prompt_requires_explicit_nonroot_user():
    """Ensure Nemotron receives the strengthened non-root rules."""
    assert "MANDATORY NON-ROOT PATCH VERIFICATION" in SYSTEM_PROMPT
    assert "USER appuser" in SYSTEM_PROMPT
    assert "Confirm the final USER is non-root" in SYSTEM_PROMPT


def test_double_escaped_line_end_is_fully_normalized():
    original = "FROM python:3.11-slim\nEXPOSE 22\n"
    malformed = (
        "FROM python:3.11-slim\n"
        "WORKDIR /app\\\\n\n"
        "RUN useradd -m appuser\n"
        "USER appuser\n"
        "EXPOSE 5000\n"
    )
    cleaned = normalize_patch_line_breaks(malformed)
    assert cleaned.splitlines()[1] == "WORKDIR /app"
    assert "\\n" not in cleaned
    assert review_patch(original, cleaned, [])["passed"] is True
