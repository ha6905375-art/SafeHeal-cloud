"""
Regression tests for USER parsing in backend/validator.py.

A model-proposed patch had "USER appuser\\n# comment" on one line (a literal
backslash-n, not a line break). The validator read the user as "appuser\\n#",
which is not "root", and accepted the patch; the AI static review rejected it.
"""

import pytest

from ai.patch_review import review_patch
from backend.validator import validate_dockerfile

BS_N = "\\n"  # the two characters backslash + n, as a model may send them
MALFORMED = "Malformed USER instruction: literal \\n instead of a line break"


def details(dockerfile):
    return validate_dockerfile(dockerfile)["details"]


def test_valid_non_root_user_passes():
    result = validate_dockerfile("FROM python:3.11-slim\nRUN useradd -m appuser\nUSER appuser\n")
    assert result == {"passed": True, "details": []}


def test_missing_user_is_rejected():
    assert "Missing non-root USER instruction" in details("FROM python:3.11-slim\nRUN useradd -m appuser\n")


@pytest.mark.parametrize("user", ["root", "ROOT", "0", "0:0"])
def test_root_user_is_rejected(user):
    assert "Container runs as root" in details(f"FROM python:3.11-slim\nUSER {user}\n")


def test_user_followed_by_escaped_newline_and_comment_is_rejected():
    # The exact failing shape: comment glued onto the USER line.
    dockerfile = f"FROM python:3.11-slim\nRUN useradd -m appuser\nUSER appuser{BS_N}# drop privileges\n"
    result = validate_dockerfile(dockerfile)
    assert result["passed"] is False
    assert MALFORMED in result["details"]
    assert "Container runs as root" not in result["details"]  # the name is read as "appuser"


def test_root_user_glued_to_comment_is_still_reported_as_root():
    result = details(f"FROM python:3.11-slim\nUSER root{BS_N}# comment\n")
    assert "Container runs as root" in result and MALFORMED in result


def test_comment_on_its_own_line_after_user_is_fine():
    dockerfile = "FROM python:3.11-slim\nRUN useradd -m appuser\nUSER appuser\n# drop privileges\nCMD [\"x\"]\n"
    assert validate_dockerfile(dockerfile)["passed"] is True


def test_escaped_newline_inside_run_is_not_flagged_as_malformed_user():
    # Only USER lines are checked for this; a printf "\n" in RUN is legitimate.
    dockerfile = 'FROM alpine\nRUN printf "a\\nb" > /tmp/f\nUSER 1000\n'
    assert validate_dockerfile(dockerfile) == {"passed": True, "details": []}


def test_multistage_uses_the_final_stage_user():
    final_ok = "FROM python:3.11 AS build\nUSER root\nFROM python:3.11-slim\nRUN useradd app\nUSER app\n"
    final_missing = "FROM python:3.11 AS build\nRUN useradd app\nUSER app\nFROM python:3.11-slim\n"
    assert validate_dockerfile(final_ok)["passed"] is True
    assert "Missing non-root USER instruction" in details(final_missing)


def test_missing_from_is_still_reported():
    assert "Missing FROM instruction" in details("USER appuser\n")


# ---------------- backend and AI static review agree on the USER cases ----------------

ORIGINAL = "FROM python:3.11-slim\n"


@pytest.mark.parametrize("patch, valid", [
    ("FROM python:3.11-slim\nRUN useradd -m appuser\nUSER appuser\n", True),
    ("FROM python:3.11-slim\nRUN useradd -m appuser\nUSER appuser\n# note\nCMD [\"x\"]\n", True),
    ("FROM python:3.11-slim\nUSER 10001\n", True),
    ("FROM python:3.11-slim\nRUN useradd -m appuser\n", False),                    # never switches
    ("FROM python:3.11-slim\nUSER root\n", False),
    (f"FROM python:3.11-slim\nRUN useradd -m appuser\nUSER appuser{BS_N}# drop privileges\n", False),
    ("FROM python:3.11 AS build\nRUN useradd app\nUSER app\nFROM python:3.11-slim\n", False),
])
def test_backend_validator_and_ai_review_agree(patch, valid):
    assert validate_dockerfile(patch)["passed"] is valid
    assert review_patch(ORIGINAL, patch, [])["passed"] is valid
