import ipaddress


def simulate_response(attack_logs):
    actions = []

    if not attack_logs:
        return {
            "mode": "simulation",
            "actions": []
        }

    events = (
        attack_logs.get("events", [])
        if isinstance(attack_logs, dict)
        else attack_logs
    )

    if not isinstance(events, list):
        return {
            "mode": "simulation",
            "actions": []
        }

    for event in events:
        if not isinstance(event, dict):
            continue

        attack_type = event.get("type")
        source_ip = event.get("source_ip")

        if attack_type not in ("port_scan", "suspicious_login"):
            continue

        if not isinstance(source_ip, str):
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

    return {
        "mode": "simulation",
        "actions": actions
    }