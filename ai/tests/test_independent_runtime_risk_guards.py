"""Independent risk guard regression tests.

The AI may omit findings; the static review still must catch selected unsafe
final-stage Dockerfile directives. No Docker build, network, or Nemotron calls.
"""
import pytest

from ai.patch_review import review_patch
from backend.validator import review_proposed_patch

BASE = 'FROM python:3.11-slim\nUSER 10001\nCMD ["python", "app.py"]\n'
OLD = (
    "FROM python:3.11-slim\n"
    "ENV DEBUG_MODE=true\n"
    "RUN apt-get update && apt-get install -y openssh-server\n"
    "EXPOSE 22\n"
)


def codes(patch, findings=None):
    result = review_patch(OLD, patch, findings or [])
    return {issue["code"] for issue in result["issues"]}


@pytest.mark.parametrize("unsafe,required", [
    ("ENV DEBUG_MODE=true\n", "debug_enabled"),
    ("ENV DEBUG_MODE='TRUE'\n", "debug_enabled"),
    ("ENV DEBUG_MODE on\n", "debug_enabled"),
    ("ENV FLASK_DEBUG=1\n", "debug_enabled"),
    ("ENV APP_DEBUG=yes\n", "debug_enabled"),
    ("ENV DEBUG_MODE=$SOME_SETTING\n", "unverified_debug_flag"),
    ("RUN apt-get install -y openssh-server\n", "ssh_server_installed"),
    ("RUN apt install --no-install-recommends openssh-server\n", "ssh_server_installed"),
    ("RUN apk add --no-cache openssh\n", "ssh_server_installed"),
    ("RUN dnf install -y openssh-server\n", "ssh_server_installed"),
    ("EXPOSE 22\n", "ssh_port_exposed"),
    ("EXPOSE 8000 22/tcp\n", "ssh_port_exposed"),
])
def test_final_stage_guards_do_not_depend_on_model_findings(unsafe, required):
    result = review_patch(OLD, BASE.replace("USER 10001\n", unsafe + "USER 10001\n"), [])
    assert result["passed"] is False
    assert required in {issue["code"] for issue in result["issues"]}, result


@pytest.mark.parametrize("benign", [
    "ENV DEBUG_MODE=false\n",
    "ENV FLASK_DEBUG=0\n",
    "ENV DEBUG_MODE=off\n",
    "RUN echo openssh-server-is-not-installed\n",
    "RUN apt-get remove -y openssh-server\n",
    "RUN apt-get install -y curl\n",
    "EXPOSE 8000\n",
])
def test_benign_lines_do_not_get_false_rejections(benign):
    patch = BASE.replace("USER 10001\n", benign + "USER 10001\n")
    assert review_patch(OLD, patch, [])["passed"] is True


def test_later_explicit_env_override_disables_debug_in_final_stage():
    patch = BASE.replace(
        "USER 10001\n",
        "ENV DEBUG_MODE=true\nENV DEBUG_MODE=false\nUSER 10001\n",
    )
    assert review_patch(OLD, patch, [])["passed"] is True


def test_build_stage_ssh_and_debug_do_not_poison_clean_runtime_stage():
    patch = (
        "FROM python:3.11-slim AS builder\n"
        "RUN apt-get install -y openssh-server\n"
        "ENV DEBUG_MODE=true\n"
        "FROM python:3.11-slim\n"
        "USER 10001\n"
        'CMD ["python", "app.py"]\n'
    )
    assert review_patch(OLD, patch, [])["passed"] is True


def test_independent_check_fails_even_if_ai_omits_every_finding():
    patch = BASE.replace(
        "USER 10001\n",
        "RUN apt-get install -y openssh-server\nENV DEBUG_MODE=true\nUSER 10001\n",
    )
    result = {
        "findings": [], "ai": {"finding_evidence": {}, "warnings": []},
        "patch": {"patched_dockerfile": patch}, "tests": {},
    }
    review_proposed_patch(OLD, result)
    assert result["tests"]["proposed_patch"]["passed"] is False
    assert result["ai"]["patch_status"] == "proposed_failed_static_review"
    assert {"ssh_server_installed", "debug_enabled"} <= {
        issue["code"] for issue in result["ai"]["patch_review"]["issues"]
    }


def test_combined_review_still_passes_clean_patch_with_no_findings():
    result = {
        "findings": [], "ai": {"finding_evidence": {}, "warnings": []},
        "patch": {"patched_dockerfile": BASE}, "tests": {},
    }
    review_proposed_patch(OLD, result)
    assert result["tests"]["proposed_patch"]["passed"] is True
    assert result["ai"]["patch_status"] == "proposed_not_validated"
