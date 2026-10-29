from backend.simulation import simulate_response


def test_legacy_port_scan():
    logs = {"events": [{"type": "port_scan", "source_ip": "192.0.2.20"}]}
    assert simulate_response(logs)["actions"] == [
        {"type": "block_ip", "target": "192.0.2.20", "reason": "port_scan", "status": "simulated"}
    ]


def test_security_engineer_event_type_port_scan():
    logs = [{"event_type": "PORT_SCAN", "source_ip": "198.51.100.45", "target_port": 22}]
    assert simulate_response(logs)["actions"][0]["reason"] == "port_scan"


def test_repeated_failed_auth_attempt_is_suspicious():
    logs = [{"event_type": "AUTH_ATTEMPT", "source_ip": "198.51.100.45",
             "status": "FAILED", "details": "Repeated unauthorized SSH login attempts (brute-force pattern)."}]
    assert simulate_response(logs)["actions"][0]["reason"] == "suspicious_login"


def test_single_auth_attempt_not_automatically_blocked():
    logs = [{"event_type": "AUTH_ATTEMPT", "source_ip": "198.51.100.45",
             "status": "FAILED", "details": "One login attempt."}]
    assert simulate_response(logs)["actions"] == []


def test_exploitation_attempt_not_misclassified():
    logs = [{"event_type": "EXPLOITATION_ATTEMPT", "source_ip": "198.51.100.45",
             "payload": "/api/debug?env=true"}]
    assert simulate_response(logs)["actions"] == []


def test_invalid_ip_is_ignored():
    logs = [{"event_type": "PORT_SCAN", "source_ip": "not-an-ip"}]
    assert simulate_response(logs)["actions"] == []


def test_duplicate_events_not_duplicate_actions():
    event = {"event_type": "PORT_SCAN", "source_ip": "198.51.100.45"}
    assert len(simulate_response([event, event])["actions"]) == 1


def test_full_security_scenario():
    logs = [
        {"event_type": "PORT_SCAN", "source_ip": "198.51.100.45",
         "target_port": 22, "status": "DETECTED"},
        {"event_type": "AUTH_ATTEMPT", "source_ip": "198.51.100.45",
         "status": "FAILED", "details": "Repeated unauthorized SSH login attempts (brute-force pattern)."},
        {"event_type": "EXPLOITATION_ATTEMPT", "source_ip": "198.51.100.45",
         "target_port": 5000, "payload": "/api/debug?env=true"}
    ]
    actions = simulate_response(logs)["actions"]
    assert [action["reason"] for action in actions] == ["port_scan", "suspicious_login"]
    assert all(action["status"] == "simulated" for action in actions)
