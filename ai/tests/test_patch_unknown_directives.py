"""Static Dockerfile patch review: reject unknown instructions (no Docker build)."""
from ai.patch_review import review_patch
from backend.validator import review_proposed_patch


VALID = (
    "FROM python:3.11-slim\n"
    "RUN useradd --create-home appuser\n"
    "USER appuser\n"
    "EXPOSE 8000\n"
    'CMD ["python", "app.py"]\n'
)


def test_known_dockerfile_instructions_remain_valid_for_static_review():
    review = review_patch("FROM python:3.11-slim\n", VALID, [])
    assert review["passed"] is True


def test_unknown_directive_cannot_pass_ai_or_combined_backend_review():
    proposed = VALID + "BOGUS package-name\n"
    review = review_patch("FROM python:3.11-slim\n", proposed, [])
    assert review["passed"] is False
    assert "unknown_instruction" in {issue["code"] for issue in review["issues"]}
    result = {"patch": {"patched_dockerfile": proposed}, "findings": [],
              "ai": {"finding_evidence": {}, "warnings": []}, "tests": {}}
    review_proposed_patch("FROM python:3.11-slim\n", result)
    assert result["tests"]["proposed_patch"]["passed"] is False
    assert result["ai"]["patch_status"] == "proposed_failed_static_review"


def test_missing_directive_argument_is_reported():
    patch = VALID + "RUN\n"
    review = review_patch("FROM python:3.11-slim\n", patch, [])
    assert review["passed"] is False
    assert "malformed_instruction" in {issue["code"] for issue in review["issues"]}
