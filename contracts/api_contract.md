# API Contract (draft)

## GET /api/health
Response: `{"status":"ok"}`

## POST /api/analyze
Request: `multipart/form-data` with `dockerfile` (required file) and `attack_logs` (optional JSON file).
Response: JSON matching `contracts/example_response.json`. `findings` and `correlations` are arrays; `patch` contains proposed Dockerfile and diff. `tests` is set by the backend after validation, not fabricated by the AI. `response.actions` contains simulated actions only.

### Status and errors (current behavior)
- `status` is `"completed"` or `"ai_error"`. The API returns HTTP 200 for both; invalid uploads still return 400/413 before any AI call.
- On `"ai_error"`: `findings` and `correlations` are `[]`, all `patch` fields are `""`, and `ai.error` is `{"code": ..., "message": ...}` (for example `config_error`, `auth_error`, `timeout`, `invalid_response`, `internal_error`). `tests` and `response` are still filled by the backend.

### `tests` (backend-owned)
- `status`, `passed`, `details`: the backend's validation of the uploaded Dockerfile.
- `proposed_patch` (only when the AI proposed a patch): `{"status": "static_review_only", "passed": ..., "details": [...]}`. A static text review only; the patch is never built, run, or applied.

### `ai` object (additive AI metadata)
- Always present: `source` (the configured mode: `"nebius"` or `"mock"`, or `"unknown"` after an unexpected failure; it is `"nebius"` even when the live call failed, so a genuine model answer is `status: "completed"` with `source: "nebius"`), `model` (or `null`), `summary`, `limitations`, `next_steps`, `warnings`, `finding_evidence` (`{finding_id: quoted Dockerfile text}`), `patch_status` (`"none"`, `"proposed_not_validated"`, or `"proposed_failed_static_review"`), `error` (`null` on success).
- Optional, only when `status` is `"completed"`: `patch_review` (static text check result) and `schema_validation` (`{"schema": "ai/output_schema.json", "valid": bool, "errors": [...]}`: whether the raw model reply matched the AI Reasoning schema before normalization). `usage` (`prompt_tokens`, `completion_tokens`, `total_tokens`) may appear only on successful live model calls.
- `patch_status: "proposed_not_validated"` means static checks passed but nothing was built or run; it is never a claim that the fix works.

**Team agreement required before implementation.** Never execute untrusted AI-generated commands or use real firewall blocking for the demo.
