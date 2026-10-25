
from backend.validator import validate_dockerfile


def test_root_user_detected():
    result = validate_dockerfile(
        "FROM python:3.11\nUSER root\n"
    )
    assert result["passed"] is False
    assert "Container runs as root" in result["details"]


def test_ssh_port_detected():
    result = validate_dockerfile(
        "FROM python:3.11\n"
        "USER appuser\n"
        "EXPOSE 22/tcp\n"
    )
    assert result["passed"] is False
    assert "SSH port 22 is exposed" in result["details"]


def test_hardcoded_secret_detected():
    result = validate_dockerfile(
        "FROM python:3.11\n"
        "USER appuser\n"
        "ENV API_KEY=supersecret123\n"
    )
    assert result["passed"] is False
    assert "Possible hardcoded secret detected" in result["details"]


def test_insecure_permissions_detected():
    result = validate_dockerfile(
        "FROM python:3.11\n"
        "USER appuser\n"
        "RUN chmod 777 /app\n"
    )
    assert result["passed"] is False
    assert "Insecure file permissions detected" in result["details"]


def test_multistage_final_user():
    result = validate_dockerfile(
        "FROM python:3.11 AS builder\n"
        "USER root\n"
        "FROM python:3.11-slim\n"
        "USER appuser\n"
    )
    assert result["passed"] is True


def test_multistage_missing_final_user():
    result = validate_dockerfile(
        "FROM python:3.11 AS builder\n"
        "USER appuser\n"
        "FROM python:3.11-slim\n"
    )
    assert result["passed"] is False
    assert "Missing non-root USER instruction" in result["details"]
