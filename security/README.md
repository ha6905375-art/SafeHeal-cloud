# Security — SafeHeal Cloud

This folder holds **intentionally insecure demonstration inputs**, not production security controls.

## What it contains

| File | Purpose |
| --- | --- |
| `vulnerable.Dockerfile` | Synthetic Dockerfile with root use, SSH exposure, a hard-coded sample secret and debug configuration |
| `attack_logs.json` | Fictional events used to demonstrate port scanning, authentication attempts and exploitation indicators |
| `Dockerfile` | Security team Dockerfile sample (check its contents before reuse) |

See the [AI rules](../ai/README.md), [backend validator](../backend/README.md) and [API contract](../contracts/api_contract.md) for the checks performed on these inputs.

## How the security analysis works

1. The backend validates the uploaded Dockerfile and optional JSON logs.
2. The AI service produces findings, evidence correlations and a **proposed** remediation Dockerfile.
3. Independent backend and AI-layer static reviews assess the proposed patch. The combined result appears in `tests.proposed_patch`.
4. Defensive responses are shown only as simulated actions; no firewall rules, container fixes or IP blocks are applied.

## Testing

Run all offline tests from the repository root:

```powershell
py -m pytest -q
```

For a demonstration use the public website's built-in mock scenario. Real Nemotron inference is separate and can consume provider credits.

## Safety limitations

The secret-looking value in the sample Dockerfile is fictional. Never use these vulnerable examples in production. A passing static review is **not** proof of a successful Docker build, secure runtime or deployed fix. The Docker Compose configuration builds the **demo website**, not the AI-generated patch.
