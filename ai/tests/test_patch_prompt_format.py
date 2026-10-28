
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
    original = 'FROM python:3.9-slim\nEXPOSE 22\nCMD ["python", "app.py"]\n'
    malformed = (
        'FROM python:3.9-slim\\n\n'
        'RUN useradd -m appuser\\n\n'
        'USER appuser\\n\n'
        'EXPOSE 5000\n'
        'CMD ["python", "app.py"]'
    )

    fixed = normalize_patch_line_breaks(malformed)

    assert "\\n" not in fixed
    assert "USER appuser" in fixed.splitlines()
    assert review_patch(original, fixed, [])["passed"] is True


def test_ambiguous_escaped_break_is_not_silently_accepted():
    original = 'FROM alpine\nEXPOSE 22\n'
    malformed = 'FROM alpine\nUSER 1000\\nEXPOSE 5000\n'

    assert normalize_patch_line_breaks(malformed) == malformed
    assert review_patch(original, malformed, [])["passed"] is False


def test_printf_escape_with_real_line_break_is_preserved():
    patch = 'FROM alpine\nRUN printf "a\\nb" > /tmp/f\nUSER 1000\n'

    assert normalize_patch_line_breaks(patch) == patch
