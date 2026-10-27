import json
import re
import sys
from pathlib import Path


# Project paths
BASE_DIR = Path(__file__).resolve().parent
TEST_DIR = BASE_DIR / "test_cases"

EXPECTED_FILE = TEST_DIR / "expected_findings.json"
DEFAULT_OUTPUT_FILE = TEST_DIR / "model_output.json"


# Keywords used for preliminary evaluation
FINDING_PATTERNS = {
    "SEC-001": r"\broot\b|\bnon-root\b",
    "SEC-002": r"\bssh\b|openssh|port 22",
    "SEC-003": r"secret|credential|aws_secret_key",
    "SEC-005": r"\bdebug\b",
}


def load_json(file_path):
    """Read and parse a JSON file."""

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def validate_output(data):
    """Check required fields for legacy and current AI outputs."""

    legacy_fields = [
        "summary",
        "risk_level",
        "findings",
        "attack_analysis",
        "patch",
        "containment_actions",
        "tests"
    ]

    current_fields = [
        "summary",
        "findings",
        "correlations",
        "patch",
        "limitations",
        "next_steps"
    ]

    if "risk_level" in data or "attack_analysis" in data:
        required_fields = legacy_fields
    else:
        required_fields = current_fields

    missing = [
        field for field in required_fields
        if field not in data
    ]

    return missing


def detect_finding(finding, pattern):
    """Check whether a finding matches a security category."""

    title = str(finding.get("title", ""))
    description = str(finding.get("description", ""))
    # Avoid counting explicit negation as a root vulnerability.
    if pattern == FINDING_PATTERNS["SEC-001"]:
        negative_root = (
            r"\bnot\s+running\s+as\s+root\b"
            r"|\bwithout\s+root\s+privileges\b"
        )

        if re.search(
            negative_root,
            title + " " + description,
            re.IGNORECASE
        ):
            return False
    evidence = finding.get("evidence", [])

    if isinstance(evidence, str):
        evidence = [evidence]
    elif not isinstance(evidence, list):
        evidence = []

    content = " ".join([
        title,
        description,
        " ".join(str(item) for item in evidence)
    ])

    return bool(re.search(pattern, content, re.IGNORECASE))


def evaluate_findings(actual, expected):
    """Compare detected findings with expected categories."""

    actual_findings = actual.get("findings", [])

    if not isinstance(actual_findings, list):
        actual_findings = []

    expected_findings = expected.get("expected_findings", [])

    detected = []
    missed = []

    for expected_finding in expected_findings:

        finding_id = expected_finding["id"]
        pattern = FINDING_PATTERNS.get(finding_id)

        if pattern is None:
            missed.append(expected_finding)
            continue

        found = any(
            isinstance(finding, dict)
            and detect_finding(finding, pattern)
            for finding in actual_findings
        )

        if found:
            detected.append(expected_finding)
        else:
            missed.append(expected_finding)

    return detected, missed


def evaluate_patch(patch):
    """Check basic patch requirements without executing it."""

    # Support the structured patch format used by AI Integration.
    if isinstance(patch, dict):
        patch = patch.get("patched_dockerfile", "")

    # Keep compatibility with the previous string format.
    if not isinstance(patch, str) or not patch.strip():
        return ["No Dockerfile patch was provided."]

    checks = {
        "Non-root USER instruction":
            bool(re.search(r"(?m)^\s*USER\s+", patch)),

        "Preserves WORKDIR":
            bool(re.search(r"(?m)^\s*WORKDIR\s+", patch)),

        "Preserves CMD":
            bool(re.search(r"(?m)^\s*CMD\s+", patch)),

        "Preserves EXPOSE 5000":
            bool(re.search(r"(?m)^\s*EXPOSE\s+5000\b", patch)),

        "Removes EXPOSE 22":
            not bool(re.search(r"(?m)^\s*EXPOSE\s+22\b", patch)),

        "Removes OpenSSH installation":
            "openssh-server" not in patch.lower(),

        "Removes hardcoded AWS_SECRET_KEY":
            not bool(
                re.search(
                    r"(?m)^\s*ENV\s+AWS_SECRET_KEY\s*[= ]",
                    patch,
                    re.IGNORECASE
                )
            )
    }

    return [
        name for name, passed in checks.items()
        if not passed
    ]

def check_unsupported_claims(actual):
    """Detect unsupported security conclusions."""

    issues = []

    # Support both legacy and current AI output formats.
    analysis_parts = [
        actual.get("attack_analysis", ""),
        actual.get("summary", "")
    ]

    findings = actual.get("findings", [])
    if isinstance(findings, list):
        for finding in findings:
            if isinstance(finding, dict):
                analysis_parts.append(finding.get("description", ""))

    correlations = actual.get("correlations", [])
    if isinstance(correlations, list):
        for correlation in correlations:
            if isinstance(correlation, dict):
                analysis_parts.append(correlation.get("explanation", ""))

    analysis = "\n".join(
        part for part in analysis_parts
        if isinstance(part, str)
    )

    unsupported_patterns = [
        r"attacker successfully compromised",
        r"attack was successful",
        r"confirmed successful compromise"
    ]

    for pattern in unsupported_patterns:
        if re.search(pattern, analysis, re.IGNORECASE):
            issues.append(
                "Model claims successful compromise without sufficient evidence."
            )
            break
    # Detect incorrect assumptions about Docker EXPOSE
    expose_patterns = [
        r"EXPOSE\s+22\s+automatically\s+makes\s+SSH\s+publicly\s+accessible",
        r"EXPOSE\s+22\s+automatically\s+exposes\s+SSH\s+to\s+the\s+internet",
        r"EXPOSE\s+22\s+means\s+SSH\s+is\s+publicly\s+accessible"
    ]

    for pattern in expose_patterns:
        if re.search(pattern, analysis, re.IGNORECASE):
            issues.append(
                "Model incorrectly assumes EXPOSE 22 makes SSH publicly accessible."
            )
            break
    return issues

def evaluate_attack_correlation(actual):
    """Check whether the AI analysis identifies key attack events."""

    logs_file = TEST_DIR / "attack_logs.json"

    if not logs_file.exists():
        print("[ERROR] Attack logs file not found.")
        return

    logs = load_json(logs_file)

    # Support legacy attack analysis.
    analysis = str(actual.get("attack_analysis", "")).lower()

    # Support structured correlations from AI Integration.
    correlations = actual.get("correlations", [])

    if isinstance(correlations, list):
        for correlation in correlations:
            if isinstance(correlation, dict):
                for field in ("event_type", "source_ip"):
                    value = correlation.get(field)

                    if isinstance(value, str):
                        analysis += "\n" + value.lower()

    print("\n--- ATTACK CORRELATION CHECK ---")

    # Extract source IPs from the attack logs
    source_ips = {
        log.get("source_ip")
        for log in logs
        if isinstance(log, dict) and log.get("source_ip")
    }

    # Extract event types
    event_types = {
        log.get("event_type")
        for log in logs
        if isinstance(log, dict) and log.get("event_type")
    }

    checks = {}

    # Check whether AI mentions the source IPs
    for ip in source_ips:
        checks[f"Source IP: {ip}"] = ip.lower() in analysis

    # Check whether AI identifies attack events
    for event in event_types:
        checks[f"Attack Event: {event}"] = event.lower() in analysis

    passed = 0

    for name, result in checks.items():
        if result:
            print(f"[PASS] {name}")
            passed += 1
        else:
            print(f"[MISSING] {name}")

    total = len(checks)

    score = (passed / total * 100) if total else 0

    print(f"\nAttack Evidence Coverage: {score:.1f}%")
    print(f"Evidence Identified: {passed}/{total}")

def evaluate_vulnerability_correlation(actual):
    """Check whether attack events are linked to relevant weaknesses."""

    analysis = str(actual.get("attack_analysis", "")).lower()

    print("\n--- ATTACK-TO-VULNERABILITY CORRELATION ---")

    # Split analysis into sentences
    sentences = re.split(r"[.!?]\s+", analysis)

    ssh_correlation = any(
        ("ssh" in sentence)
        and ("openssh-server" in sentence or "expose 22" in sentence)
        and ("relevant" in sentence or "related" in sentence or "linked" in sentence)
        for sentence in sentences
    )

    debug_correlation = any(
        ("debug endpoint" in sentence or "exploitation_attempt" in sentence)
        and ("debug_mode" in sentence or "credential" in sentence)
        and ("relevant" in sentence or "related" in sentence or "linked" in sentence)
        for sentence in sentences
    )
    # Evaluate structured correlations from AI Integration.
    if isinstance(actual.get("correlations"), list):

        ssh_correlation = False
        debug_correlation = False

        findings_by_id = {
            finding["id"]: finding
            for finding in actual.get("findings", [])
            if isinstance(finding, dict)
            and isinstance(finding.get("id"), str)
        }

        for correlation in actual["correlations"]:

            if not isinstance(correlation, dict):
                continue

            event_type = correlation.get("event_type")
            related_ids = correlation.get("related_finding_ids", [])

            if not isinstance(related_ids, list):
                continue

            for finding_id in related_ids:

                finding = findings_by_id.get(finding_id)

                if not finding:
                    continue

                finding_text = (
                    str(finding.get("title", "")) + " " +
                    str(finding.get("description", ""))
                ).lower()

                if event_type == "AUTH_ATTEMPT":
                    if "ssh" in finding_text or "openssh" in finding_text:
                        ssh_correlation = True

                if event_type == "EXPLOITATION_ATTEMPT":
                    if "debug" in finding_text or "credential" in finding_text:
                        debug_correlation = True
    checks = {
        "SSH attack linked to SSH configuration": ssh_correlation,
        "Debug attack linked to sensitive configuration": debug_correlation
    }

    passed = 0

    for name, result in checks.items():
        if result:
            print(f"[PASS] {name}")
            passed += 1
        else:
            print(f"[MISSING] {name}")

    total = len(checks)

    print(f"\nCorrelation Coverage: {passed / total * 100:.1f}%")
    print(f"Correlations Identified: {passed}/{total}")

def evaluate_terraform():
    """Evaluate Terraform security findings."""

    expected_file = TEST_DIR / "terraform_expected_findings.json"
    output_file = TEST_DIR / "terraform_model_output.json"

    print("\n--- TERRAFORM SECURITY EVALUATION ---")

    if not expected_file.exists():
        print("[ERROR] Terraform expected findings file not found.")
        return

    if not output_file.exists():
        print("[INFO] Terraform model output not available yet.")
        print("Terraform evaluation will run when output is provided.")
        return

    try:
        expected = load_json(expected_file)
        actual = load_json(output_file)

    except (json.JSONDecodeError, OSError) as error:
        print(f"[ERROR] Could not read Terraform JSON: {error}")
        return

    if not isinstance(expected, dict) or not isinstance(actual, dict):
        print("[ERROR] Terraform data must be JSON objects.")
        return

    expected_findings = expected.get("expected_findings", [])
    actual_findings = actual.get("findings", [])

    if not isinstance(expected_findings, list) or not isinstance(actual_findings, list):
        print("[ERROR] Findings must be lists.")
        return

    detected = 0

    for expected_finding in expected_findings:

        title = expected_finding.get("title", "")

        found = any(
            isinstance(finding, dict)
            and finding.get("title", "").strip().lower() == title.lower()
            for finding in actual_findings
            if isinstance(finding.get("title", ""), str)
        )

        if found:
            print(f"[DETECTED] {title}")
            detected += 1
        else:
            print(f"[MISSED] {title}")

    total = len(expected_findings)

    score = (detected / total * 100) if total else 0

    print(f"\nTerraform Detection Coverage: {score:.1f}%")
    print(f"Detected: {detected}/{total}")

    print("\nNote: This is a preliminary title-matching evaluation.")
def main():

    output_file = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else DEFAULT_OUTPUT_FILE
    )

    if not EXPECTED_FILE.exists():
        print("ERROR: expected_findings.json not found.")
        return

    if not output_file.exists():
        print("Nemotron output file not found yet.")
        print(f"Expected path: {output_file}")
        print("Save the model response as model_output.json.")
        return

    try:
        expected = load_json(EXPECTED_FILE)
        actual = load_json(output_file)

    except (json.JSONDecodeError, OSError) as error:
        print(f"ERROR reading JSON: {error}")
        return

    if not isinstance(actual, dict):
        print("ERROR: Model output must be a JSON object.")
        return

    print("\n===== CYBER DEFENSE AI EVALUATION =====\n")

    # Check output structure
    missing_fields = validate_output(actual)

    if missing_fields:
        print("Missing output fields:")
        for field in missing_fields:
            print(f"  - {field}")
    else:
        print("[PASS] Required output fields are present.")

    # Evaluate security findings
    detected, missed = evaluate_findings(actual, expected)

    total = len(expected.get("expected_findings", []))
    score = len(detected) / total * 100 if total else 0

    print("\n--- SECURITY FINDINGS ---")

    for finding in detected:
        print(f"[DETECTED] {finding['title']}")

    for finding in missed:
        print(f"[MISSED]   {finding['title']}")

    print(f"\nPreliminary detection coverage: {score:.1f}%")
    print(f"Detected: {len(detected)} / {total}")

    # Evaluate generated patch
    print("\n--- PATCH CHECKS ---")

    patch_issues = evaluate_patch(actual.get("patch"))

    if patch_issues:
        for issue in patch_issues:
            print(f"[CHECK] {issue}")
    else:
        print("[PASS] Basic patch checks passed.")

    print("\nNote: These are static checks only.")
    print("A successful Docker build and runtime test")
    print("are still required to verify the patch.")
    print("\n--- UNSUPPORTED CLAIMS CHECK ---")

    claim_issues = check_unsupported_claims(actual)

    if claim_issues:
        for issue in claim_issues:
            print(f"[WARNING] {issue}")
    else:
        print("[PASS] No predefined unsupported claims detected.")
    evaluate_attack_correlation(actual)
    evaluate_vulnerability_correlation(actual)
    evaluate_terraform()
    print("\n===== EVALUATION COMPLETE =====")


if __name__ == "__main__":
    main()