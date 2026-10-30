"""An unchanged *safe context line* is not an unresolved security finding.

The model may cite FROM/CMD/EXPOSE 8000 as context for missing USER.
Only concrete unsafe unchanged instructions should trigger unresolved_finding.
No external AI calls or Docker builds.
"""
from ai.patch_review import review_patch
from backend.validator import review_proposed_patch

ORIGINAL = (
    "FROM python:3.11-slim\n"
    "ENV API_TOKEN=SYNTHETIC_DEMO_VALUE\n"
    "ENV DEBUG_MODE=true\n"
    "RUN apt-get update && apt-get install -y openssh-server\n"
    "EXPOSE 22\n"
    "EXPOSE 8000\n"
    'CMD ["python", "app.py"]\n'
)
GOOD_PATCH = (
    "FROM python:3.11-slim\n"
    "RUN useradd --create-home appuser\n"
    "USER appuser\n"
    "EXPOSE 8000\n"
    'CMD ["python", "app.py"]\n'
)
FINDINGS = [
    {"id": "F-001", "title": "Container runs as root",
     "evidence": 'FROM python:3.11-slim\nCMD ["python", "app.py"]'},
    {"id": "F-002", "title": "SSH port 22 exposed",
     "evidence": "EXPOSE 22"},
    {"id": "F-003", "title": "SSH server installed",
     "evidence": "RUN apt-get update && apt-get install -y openssh-server"},
    {"id": "F-004", "title": "Hardcoded secret",
     "evidence": "ENV API_TOKEN=SYNTHETIC_DEMO_VALUE"},
    {"id": "F-005", "title": "Debug mode enabled",
     "evidence": "ENV DEBUG_MODE=true"},
]


def test_changed_unsafe_lines_with_same_safe_context_do_not_trigger_false_failure():
    result = review_patch(ORIGINAL, GOOD_PATCH, FINDINGS)
    assert result["passed"] is True, result["issues"]
    assert result["issues"] == []


def test_backend_and_ai_layer_agree_on_fixed_context_case():
    result = {
        "findings": [{"id": f["id"], "title": f["title"]} for f in FINDINGS],
        "ai": {"finding_evidence": {f["id"]: f["evidence"] for f in FINDINGS}},
        "patch": {"patched_dockerfile": GOOD_PATCH},
        "tests": {},
    }
    review_proposed_patch(ORIGINAL, result)
    assert result["tests"]["proposed_patch"]["passed"] is True
    assert result["ai"]["patch_status"] == "proposed_not_validated"


def test_retained_openssh_package_still_fails_even_if_ports_are_removed():
    unsafe = GOOD_PATCH.replace(
        "USER appuser\n",
        "RUN apt-get update && apt-get install -y openssh-server\nUSER appuser\n",
    )
    result = review_patch(ORIGINAL, unsafe, FINDINGS)
    assert "unresolved_finding" in {issue["code"] for issue in result["issues"]}
    assert result["passed"] is False


def test_retained_debug_mode_still_fails():
    unsafe = GOOD_PATCH.replace("USER appuser\n", "ENV DEBUG_MODE=true\nUSER appuser\n")
    result = review_patch(ORIGINAL, unsafe, FINDINGS)
    assert "unresolved_finding" in {issue["code"] for issue in result["issues"]}


def test_retained_ssh_port_still_fails():
    unsafe = GOOD_PATCH.replace("EXPOSE 8000\n", "EXPOSE 22\nEXPOSE 8000\n")
    result = review_patch(ORIGINAL, unsafe, FINDINGS)
    assert "unresolved_finding" in {issue["code"] for issue in result["issues"]}


def test_retained_secret_evidence_does_not_appear_in_review_message():
    unsafe = GOOD_PATCH.replace(
        "USER appuser\n", "ENV API_TOKEN=SYNTHETIC_DEMO_VALUE\nUSER appuser\n",
    )
    result = review_patch(ORIGINAL, unsafe, FINDINGS)
    assert {"unresolved_finding", "hardcoded_secret"} <= {
        issue["code"] for issue in result["issues"]
    }
    assert "SYNTHETIC_DEMO_VALUE" not in str(result["issues"])


def test_unpinned_nonpython_base_with_related_finding_remains_unresolved():
    original = "FROM alpine:latest\n"
    patch = original + "USER 1000\n"
    finding = {"id": "F-001", "title": "Unpinned base image",
               "evidence": "FROM alpine:latest"}
    result = review_patch(original, patch, [finding])
    assert "unresolved_finding" in {issue["code"] for issue in result["issues"]}


def test_unrelated_copy_context_does_not_block_safe_remediation():
    original = "FROM python:3.11-slim\nCOPY . .\nCMD python app.py\n"
    patch = "FROM python:3.11-slim\nCOPY . .\nUSER 1000\nCMD python app.py\n"
    result = review_patch(original, patch, [
        {"id": "F-001", "title": "Container runs as root",
         "evidence": "COPY . .\nCMD python app.py"},
    ])
    assert result["passed"] is True, result["issues"]
