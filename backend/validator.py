import re


def validate_dockerfile(dockerfile_text: str):
    issues = []

    if not dockerfile_text.strip():
        issues.append("Dockerfile is empty")
        return {
            "passed": False,
            "details": issues
        }

    # Remove blank lines and comments
    lines = [
        line.strip()
        for line in dockerfile_text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    instructions = []

    for line in lines:
        match = re.match(r"^([A-Za-z]+)\s+(.*)$", line)

        if match:
            instructions.append(
                (match.group(1).upper(), match.group(2).strip())
            )

    # Check base image
    if not any(name == "FROM" for name, value in instructions):
        issues.append("Missing FROM instruction")

    # Check final user configuration
    users = [
        value for name, value in instructions
        if name == "USER"
    ]

    if not users:
        issues.append("Missing non-root USER instruction")
    elif users[-1].lower() in ("root", "0", "0:0"):
        issues.append("Container runs as root")

    # Check exposed ports
    for name, value in instructions:
        if name == "EXPOSE":
            ports = value.split()

            if "22" in ports or "22/tcp" in ports:
                issues.append("SSH port 22 is exposed")

    # Check obvious hardcoded secrets
    for name, value in instructions:
        if name in ("ENV", "ARG"):
            if re.search(
                r"(PASSWORD|SECRET|API_KEY|TOKEN)\s*=\s*['\"]?[^$\s'\"]+",
                value,
                re.IGNORECASE
            ):
                issues.append("Possible hardcoded secret detected")

    return {
        "passed": len(issues) == 0,
        "details": issues
    }