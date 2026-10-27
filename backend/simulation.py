import ipaddress


def _normalize_attack_type(event):
    """Map supported Security and legacy log events to simulation reasons."""
    raw = event.get("type") or event.get("event_type")
    if not isinstance(raw, str):
        return None

    event_type = raw.strip().lower()
    if event_type in ("port_scan", "suspicious_login"):
        return event_type

    # A generic authentication attempt is not necessarily an attack.
    # Only simulate blocking when the log explicitly describes repeated failed attempts.
    if event_type == "auth_attempt":
        status = str(event.get("status") or "").strip().lower()
        details = str(event.get("details") or "").lower()
        if status == "failed" and any(term in details for term in ("repeated", "brute-force", "brute force")):
            return "suspicious_login"

    return None


def simulate_response(attack_logs):
    actions = []

    if not attack_logs:
        return {"mode": "simulation", "actions": []}

    events = (
        attack_logs.get("events", [])
        if isinstance(attack_logs, dict)
        else attack_logs
    )

    if not isinstance(events, list):
        return {"mode": "simulation", "actions": []}

    for event in events:
        if not isinstance(event, dict):
            continue

        attack_type = _normalize_attack_type(event)
        source_ip = event.get("source_ip")

        if attack_type is None or not isinstance(source_ip, str):
            continue

        try:
            ipaddress.ip_address(source_ip)
        except ValueError:
            continue

        action = {
            "type": "block_ip",
            "target": source_ip,
            "reason": attack_type,
            "status": "simulated"
        }

        if action not in actions:
            actions.append(action)

    return {"mode": "simulation", "actions": actions}
