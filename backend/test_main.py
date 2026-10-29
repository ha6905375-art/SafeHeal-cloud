import io

from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def upload_files(dockerfile_content, logs_content=None):
    files = {
        "dockerfile": (
            "Dockerfile",
            io.BytesIO(dockerfile_content),
            "text/plain"
        )
    }

    if logs_content is not None:
        files["attack_logs"] = (
            "attack_logs.json",
            io.BytesIO(logs_content),
            "application/json"
        )

    return client.post("/api/analyze", files=files)


def test_health_check():
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_valid_dockerfile():
    response = upload_files(
        b"FROM python:3.11-slim\nUSER appuser\n"
    )

    assert response.status_code == 200
    assert response.json()["tests"]["passed"] is True


def test_missing_non_root_user():
    response = upload_files(
        b"FROM python:3.11-slim\n"
    )

    assert response.status_code == 200
    assert response.json()["tests"]["passed"] is False


def test_empty_dockerfile():
    response = upload_files(b"")

    assert response.status_code == 400


def test_invalid_json():
    response = upload_files(
        b"FROM python:3.11-slim\n",
        b'{"events": ['
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid JSON attack logs"


def test_security_simulation():
    logs = b'''
    {
        "events": [
            {
                "type": "port_scan",
                "source_ip": "192.0.2.20"
            }
        ]
    }
    '''

    response = upload_files(
        b"FROM python:3.11-slim\nUSER appuser\n",
        logs
    )

    assert response.status_code == 200

    actions = response.json()["response"]["actions"]

    assert len(actions) == 1
    assert actions[0]["type"] == "block_ip"
    assert actions[0]["status"] == "simulated"


def test_file_too_large():
    response = upload_files(
        b"A" * (1024 * 1024 + 1)
    )

    assert response.status_code == 413