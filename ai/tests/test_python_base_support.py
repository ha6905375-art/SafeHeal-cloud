"""Regression tests for unsupported official Python image tags in AI patches.

Only static Dockerfile text analysis: no image build, network, or Nebius usage.
"""
from pathlib import Path
import pytest

from ai.patch_review import review_patch
from ai.prompts import SYSTEM_PROMPT
from ai.service import analyze_evidence
from ai.tests.test_ai_integration import MOCK
from backend.validator import review_proposed_patch

SAFE_TAIL = 'USER 1000\nCMD ["python", "app.py"]\n'


@pytest.mark.parametrize("base", [
    "FROM python:3.9-slim",
    "FROM python:3.10-slim",
    "FROM python:3.9.25-alpine",
    "FROM python:3.10.22",
    "FROM docker.io/library/python:3.9-slim AS builder",
    "FROM --platform=linux/amd64 python:3.10-slim AS runtime",
    "FROM python:2.7-slim",
])
def test_eol_python_is_rejected(base):
    result = review_patch("FROM alpine:3.20\n", base + "\n" + SAFE_TAIL, [])
    assert result["passed"] is False
    assert "unsupported_python_base" in {issue["code"] for issue in result["issues"]}


@pytest.mark.parametrize("base", [
    "FROM python:3.11-slim",
    "FROM python:3.12-slim",
    "FROM python:3.13-alpine",
    "FROM python:3.14-slim",
    "FROM python:3.15",
    "FROM --platform=linux/amd64 python:3.11-slim AS runtime",
    "FROM node:20-alpine",
    "FROM registry.example.org/custom/python:3.9-slim",
])
def test_supported_or_nonofficial_images_not_falsely_marked_eol(base):
    result = review_patch("FROM alpine:3.20\n", base + "\n" + SAFE_TAIL, [])
    assert result["passed"] is True, result["issues"]


@pytest.mark.parametrize("base", [
    "FROM python:latest",
    "FROM python:3",
    "FROM python",
    "FROM python:${PYTHON_VERSION}-slim",
])
def test_unverifiable_official_python_tag_is_not_static_pass(base):
    result = review_patch("FROM alpine:3.20\n", base + "\n" + SAFE_TAIL, [])
    assert result["passed"] is False
    assert "unverified_python_base_version" in {item["code"] for item in result["issues"]}


def test_build_stage_eol_fails_even_if_final_stage_supported():
    proposed = (
        "FROM python:3.9-slim AS builder\nRUN python -V\n"
        "FROM python:3.11-slim\nUSER 1000\nCOPY --from=builder /tmp/app /app\n"
    )
    result = review_patch("FROM alpine:3.20\n", proposed, [])
    assert "unsupported_python_base" in {i["code"] for i in result["issues"]}
    assert result["passed"] is False


def test_combined_backend_review_rejects_eol_patch():
    proposed = "FROM python:3.9-slim\n" + SAFE_TAIL
    result = {
        "patch": {"patched_dockerfile": proposed},
        "findings": [],
        "ai": {"finding_evidence": {}, "warnings": []},
        "tests": {},
    }
    review_proposed_patch("FROM python:3.9-slim\n", result)
    assert result["tests"]["proposed_patch"]["passed"] is False
    assert result["ai"]["patch_status"] == "proposed_failed_static_review"
    assert any("end-of-life" in detail for detail in result["tests"]["proposed_patch"]["details"])


def test_mock_classic_demo_still_proposes_patch_with_supported_python():
    docker = (Path(__file__).resolve().parents[2] /
              "security" / "vulnerable.Dockerfile").read_text(encoding="utf-8")
    result = analyze_evidence(docker, [], settings=MOCK)
    assert result["status"] == "completed"
    assert result["ai"]["source"] == "mock"
    assert "Unsupported Python base image" in {f["title"] for f in result["findings"]}
    assert "FROM python:3.11-slim" in result["patch"]["patched_dockerfile"]
    assert "FROM python:3.9-slim" not in result["patch"]["patched_dockerfile"]
    assert result["ai"]["patch_status"] == "proposed_not_validated"
    assert "compatibility" in " ".join(result["limitations"]).lower()


def test_nemotron_system_prompt_does_not_recommend_eol_python():
    assert "FROM python:3.11-slim" in SYSTEM_PROMPT
    assert "FROM python:3.9-slim" not in SYSTEM_PROMPT
    assert "Python 3.9 and 3.10 are end-of-life" in SYSTEM_PROMPT
