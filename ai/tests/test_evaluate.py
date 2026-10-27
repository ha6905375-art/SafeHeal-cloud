"""Tests for the AI Reasoning evaluator (ai/evaluate.py) and its fixtures."""

import json
from pathlib import Path

import pytest

from ai import evaluate as ev

TEST_CASES = Path(__file__).resolve().parents[1] / "test_cases"
EXPECTED = json.loads((TEST_CASES / "expected_findings.json").read_text(encoding="utf-8"))
GOOD_PATCH = (
    "FROM python:3.11-slim\n"
    "RUN groupadd -r appuser && useradd -r -g appuser appuser\n"
    "WORKDIR /app\n"
    "COPY requirements.txt .\n"
    "RUN pip install --no-cache-dir -r requirements.txt\n"
    "COPY --chown=appuser:appuser . .\n"
    "USER appuser\n"
    "EXPOSE 5000\n"
    'CMD ["python", "app.py"]'
)


def finding(title, description="", evidence=""):
    return {"title": title, "description": description, "evidence": evidence}


def detected_ids(findings):
    detected, _ = ev.evaluate_findings({"findings": findings}, EXPECTED)
    return {f["id"] for f in detected}


# ---------------- fixtures ----------------

@pytest.mark.parametrize("fixture", ["model_output.json", "sara_format_sample.json"])
def test_fixtures_detect_all_expected_findings(fixture):
    actual = json.loads((TEST_CASES / fixture).read_text(encoding="utf-8"))
    detected, missed = ev.evaluate_findings(actual, EXPECTED)
    assert missed == []
    assert len(detected) == len(EXPECTED["expected_findings"]) == 4


@pytest.mark.parametrize("fixture", ["model_output.json", "sara_format_sample.json"])
def test_root_user_fixture_is_consistent_with_vulnerable_dockerfile(fixture):
    dockerfile = (TEST_CASES / "vulnerable.Dockerfile").read_text(encoding="utf-8")
    assert "USER" not in dockerfile  # so the container runs as root
    actual = json.loads((TEST_CASES / fixture).read_text(encoding="utf-8"))
    root = [f for f in actual["findings"] if ev.detect_finding(f, ev.FINDING_PATTERNS["SEC-001"])]
    assert len(root) == 1
    text = json.dumps(root[0]).lower()
    assert "not running as root" not in text and "without root privileges" not in text
    assert "no user instruction" in text


@pytest.mark.parametrize("fixture", ["model_output.json", "sara_format_sample.json"])
def test_fixture_patch_passes_and_has_no_unsupported_claims(fixture):
    actual = json.loads((TEST_CASES / fixture).read_text(encoding="utf-8"))
    assert ev.evaluate_patch(actual["patch"]) == []
    assert ev.check_unsupported_claims(actual) == []


def test_current_format_fixture_matches_schema():
    actual = json.loads((TEST_CASES / "sara_format_sample.json").read_text(encoding="utf-8"))
    assert not ev.is_legacy_format(actual)
    assert ev.validate_output(actual) == []
    assert ev.schema_errors(actual) == []


# ---------------- --run: evaluate the real pipeline output ----------------

def test_run_mock_pipeline_output_is_evaluated(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["evaluate.py", "--run", "mock"])
    assert ev.main() == 0
    out = capsys.readouterr().out
    assert "Source: mock" in out
    assert "[PASS] Output matches ai/output_schema.json." in out
    assert "Detected: 4 / 4" in out
    assert "AKIAIOSFODNN7EXAMPLE" not in out  # secret is redacted by the service


def test_run_live_without_credentials_fails_without_fake_results(monkeypatch, capsys):
    # Empty env vars win over any local .env, so this never calls the real API.
    monkeypatch.setenv("NEBIUS_API_KEY", "")
    monkeypatch.setenv("NEBIUS_MODEL", "")
    monkeypatch.setattr("sys.argv", ["evaluate.py", "--run", "live"])
    assert ev.main() == 1
    out = capsys.readouterr().out
    assert "config_error" in out and "DETECTED" not in out


def test_service_result_conversion_restores_evidence():
    result = {
        "findings": [{"id": "F-001", "title": "t", "severity": "HIGH", "description": "d", "recommendation": "r"}],
        "correlations": [],
        "patch": {"patched_dockerfile": "FROM x\n", "diff": "--- a\n+++ b\n", "summary": "s"},
        "ai": {"summary": "s", "limitations": [], "next_steps": [], "finding_evidence": {"F-001": "EXPOSE 22"}},
    }
    converted = ev.service_result_to_model_output(result)
    assert converted["findings"][0]["evidence"] == "EXPOSE 22"
    assert converted["patch"]["diff"] == ""
    assert ev.schema_errors(converted) == []


# ---------------- SEC-001 root user ----------------

def test_contradictory_root_finding_is_not_counted():
    """The original fixture bug: title says NOT root, evidence says no USER."""
    bad = finding("Container is NOT running as root",
                  "The container is configured to run without root privileges.",
                  ["No USER instruction found"])
    assert "SEC-001" not in detected_ids([bad])


@pytest.mark.parametrize("item", [
    finding("Container Running as Root"),
    finding("Missing USER instruction", "Without a USER line the process defaults to root."),
    finding("Least privilege", evidence="No USER instruction is present"),
    finding("No non-root user", "Create a dedicated non-root user."),
])
def test_root_user_finding_variants_are_detected(item):
    assert "SEC-001" in detected_ids([item])


@pytest.mark.parametrize("item", [
    finding("Unnecessary SSH Service", "Logs show a failed SSH login attempt for the root account.",
            ["openssh-server installed"]),
    finding("Container already runs as a non-root user", evidence="USER appuser"),
    finding("Least privilege OK", "The container does not run as root."),
])
def test_unrelated_root_mentions_are_not_counted_as_root_user(item):
    assert "SEC-001" not in detected_ids([item])


# ---------------- other categories ----------------

def test_ssh_credential_guessing_is_not_a_hardcoded_secret():
    ssh = finding("Unnecessary SSH Service", "Exposes the container to SSH credential guessing.",
                  ["openssh-server installed"])
    assert detected_ids([ssh]) == {"SEC-002"}


@pytest.mark.parametrize("item", [
    finding("Hardcoded Credential"),
    finding("Sensitive environment variable", evidence="ENV AWS_SECRET_KEY=[REDACTED]"),
    finding("Secret exposure", "A secret value is stored in an ENV instruction."),
])
def test_hardcoded_secret_variants_are_detected(item):
    assert "SEC-003" in detected_ids([item])


def test_debug_mode_detected_from_evidence_only():
    """\\bdebug\\b alone does not match DEBUG_MODE (underscore is a word character)."""
    item = finding("Insecure runtime configuration", evidence=['ENV DEBUG_MODE="true"'])
    assert "SEC-005" in detected_ids([item])


def test_expose_22_counts_as_ssh_finding():
    assert "SEC-002" in detected_ids([finding("Unneeded port", evidence="EXPOSE 22")])


# ---------------- patch checks ----------------

def test_good_patch_passes_all_checks():
    assert ev.evaluate_patch(GOOD_PATCH) == []
    assert ev.evaluate_patch({"patched_dockerfile": GOOD_PATCH}) == []


@pytest.mark.parametrize("patch, failed", [
    (GOOD_PATCH.replace("USER appuser", "USER root"), "Non-root USER instruction"),
    (GOOD_PATCH.replace("USER appuser", "USER 0"), "Non-root USER instruction"),
    (GOOD_PATCH.replace("RUN groupadd -r appuser && useradd -r -g appuser appuser\n", ""),
     "Non-root user is created before USER"),
    (GOOD_PATCH.replace("RUN groupadd -r appuser && useradd -r -g appuser appuser\n", "")
     .replace("USER appuser", "USER appuser\nRUN useradd appuser"), "Non-root user is created before USER"),
    (GOOD_PATCH.replace("WORKDIR /app", 'WORKDIR /app\nARG AWS_SECRET_KEY="x"'), "Removes hardcoded AWS_SECRET_KEY"),
    (GOOD_PATCH.replace("WORKDIR /app", "WORKDIR /app\nENV AWS_KEY=AKIAIOSFODNN7EXAMPLE"),
     "Does not reproduce the original secret value"),
    (GOOD_PATCH.replace("EXPOSE 5000", "EXPOSE 5000\nEXPOSE 22"), "Removes EXPOSE 22"),
    (GOOD_PATCH + "\nRUN apt-get install -y openssh-server", "Removes OpenSSH installation"),
])
def test_bad_patches_are_flagged(patch, failed):
    assert failed in ev.evaluate_patch(patch)


def test_numeric_user_needs_no_useradd():
    patch = GOOD_PATCH.replace("RUN groupadd -r appuser && useradd -r -g appuser appuser\n", "")
    assert ev.evaluate_patch(patch.replace("USER appuser", "USER 10001")) == []


def test_missing_patch_is_reported():
    assert ev.evaluate_patch(None) == ["No Dockerfile patch was provided."]
    assert ev.evaluate_patch({"patched_dockerfile": ""}) == ["No Dockerfile patch was provided."]


# ---------------- unsupported claims ----------------

@pytest.mark.parametrize("text, issue", [
    ("The attacker successfully compromised the container.", "successful compromise"),
    ("EXPOSE 22 automatically makes SSH publicly accessible.", "EXPOSE 22"),
    ("The patch was successfully tested.", "tested or applied"),
    ("The AWS key is a confirmed valid secret.", "confirmed valid secret"),
])
def test_unsupported_claims_are_flagged(text, issue):
    issues = ev.check_unsupported_claims({"summary": text})
    assert any(issue in i for i in issues), issues


def test_patch_summary_claims_are_checked():
    actual = {"summary": "ok", "patch": {"summary": "Patch has been verified and applied."}}
    assert ev.check_unsupported_claims(actual)


def test_cautious_wording_is_not_flagged():
    text = ("Suspicious activity; the logs do not confirm a successful compromise. "
            "The proposed patch has not been tested.")
    assert ev.check_unsupported_claims({"summary": text}) == []
