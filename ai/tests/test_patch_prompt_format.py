"""Ensure integration instructions address the malformed live Nemotron patch."""

from ai.prompts import SYSTEM_PROMPT
from ai.patch_review import review_patch
from ai.response_parser import normalize_patch_line_breaks


def test_prompt_requires_real_decoded_dockerfile_line_breaks():
    assert "patch.patched_dockerfile" in SYSTEM_PROMPT
    assert "REAL newline" in SYSTEM_PROMPT
    assert "double-escape" in SYSTEM_PROMPT
    assert "one instruction per line" in SYSTEM_PROMPT


def test_mixed_real_and_literal_breaks_remain_untrusted():
    original = 'FROM python:3.9-slim\nEXPOSE 22\nCMD ["python", "app.py"]\n'
    malformed = (
        'FROM python:3.9-slim\\n\n'
        'RUN useradd -m appuser\\n\n'
        'USER appuser\\n\n'
        'EXPOSE 5000\n'
        'CMD [\\"python\\", \\"app.py\\"]'
    )
    assert normalize_patch_line_breaks(malformed) == malformed
    result = review_patch(original, malformed, [])
    assert not result["passed"]
    assert "malformed_line_breaks" in {item["code"] for item in result["issues"]}


def test_live_redundant_escaped_breaks_before_real_newlines_are_cleaned():
    # Regression from the live backend request: literal \\n immediately before
    # real newlines, mixed with already-correct Dockerfile lines.
    malformed = (
        'FROM python:3.9-slim\\\\n\\n'
        'WORKDIR /app\\\\n\\n'
        'COPY requirements.txt .\\n'
        'RUN pip install --no-cache-dir -r requirements.txt\\\\n\\n'
        'RUN useradd -m appuser\\\\n\\n'
        'COPY . .\\\\n\\n'
        'EXPOSE 5000\\\\n\\n'
        'USER appuser\\\\n\\n'
        'CMD ["python", "app.py"]'
    )
    fixed = normalize_patch_line_breaks(malformed)
    assert "\\\\n" not in fixed
    assert "USER appuser" in fixed.splitlines()
    assert review_patch('FROM python:3.9-slim\\nEXPOSE 22\\n', fixed, [])["passed"] is True


def test_printf_escape_with_real_line_break_is_preserved():
    patch = 'FROM alpine\\nRUN printf "a\\\\nb" > /tmp/f\\nUSER 1000\\n'
    assert normalize_patch_line_breaks(patch) == patch
