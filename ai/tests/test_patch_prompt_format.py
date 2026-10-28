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
