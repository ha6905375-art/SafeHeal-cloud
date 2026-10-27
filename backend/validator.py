
import re


def validate_dockerfile(dockerfile_text: str):
    issues = []

    if not dockerfile_text.strip():
        return {
            "passed": False,
            "details": ["Dockerfile is empty"]
        }

    # Join continued lines
    text = re.sub(r"\\\r?\n\s*", " ", dockerfile_text)

    instructions = []

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        match = re.match(r"^([A-Za-z]+)\s+(.+)$", line)

        if match:
            instructions.append(
                (match.group(1).upper(), match.group(2).strip())
            )

    # Check the final build stage
    stages = []
    current_stage = None

    for name, value in instructions:
        if name == "FROM":
            current_stage = {"user": None}
            stages.append(current_stage)

        elif name == "USER" and current_stage is not None:
            # The name ends at whitespace or at a literal "\n" (two characters),
            # so text glued on by an escaped line break is not read as the name.
            current_stage["user"] = re.split(r"\s|\\n", value, maxsplit=1)[0]
            if "\\n" in value:
                issues.append(
                    "Malformed USER instruction: literal \\n instead of a line break"
                )

    if not stages:
        issues.append("Missing FROM instruction")
    else:
        final_user = stages[-1]["user"]

        if final_user is None:
            issues.append("Missing non-root USER instruction")
        elif final_user.lower() in ("root", "0", "0:0"):
            issues.append("Container runs as root")

    # Detect SSH port 22
    for name, value in instructions:
        if name == "EXPOSE":
            for port in value.split():
                if port.split("/")[0] == "22":
                    issues.append("SSH port 22 is exposed")
                    break

    # Detect hardcoded secrets
    secret_pattern = re.compile(
        r"(PASSWORD|PASSWD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)",
        re.IGNORECASE
    )

    for name, value in instructions:
        if name not in ("ENV", "ARG"):
            continue

        assignments = re.findall(
            r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
            r"(?:\"([^\"]*)\"|'([^']*)'|([^\s]+))",
            value
        )

        for key, double_value, single_value, plain_value in assignments:
            secret_value = double_value or single_value or plain_value

            if (
                secret_pattern.search(key)
                and secret_value
                and not secret_value.startswith("$")
            ):
                issues.append("Possible hardcoded secret detected")
                break

    # Detect unsafe chmod permissions
    for name, value in instructions:
        if name == "RUN":
            if re.search(
                r"\bchmod\s+(?:-R\s+)?777\b",
                value,
                re.IGNORECASE
            ):
                issues.append("Insecure file permissions detected")
                break

    return {
        "passed": len(issues) == 0,
        "details": list(dict.fromkeys(issues))
    }
