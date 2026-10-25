# API Contract (draft)

## GET /api/health
Response: `{"status":"ok"}`

## POST /api/analyze
Request: `multipart/form-data` with `dockerfile` (required file) and `attack_logs` (optional JSON file).
Response: JSON matching `contracts/example_response.json`. `findings` and `correlations` are arrays; `patch` contains proposed Dockerfile and diff. `tests` is set by the backend after validation, not fabricated by the AI. `response.actions` contains simulated actions only.

**Team agreement required before implementation.** Never execute untrusted AI-generated commands or use real firewall blocking for the demo.
