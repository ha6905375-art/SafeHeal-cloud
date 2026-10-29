# Contracts — SafeHeal Cloud API

This folder documents the current interface shared by the webapp, backend, AI integration and security validation.

## Files

| File | Purpose |
| --- | --- |
| [`api_contract.md`](api_contract.md) | Request/response shapes, endpoints, authentication and validation semantics |
| [`example_response.json`](example_response.json) | Example result format for integration and demonstrations |

## Key endpoint and fields

- `GET /api/health` returns the service health result.
- `POST /api/analyze` accepts a UTF-8 upload named `Dockerfile` and optional JSON attack logs.
- A completed analysis returns `status`, `findings`, `correlations`, `patch`, `tests`, `response` and `ai` metadata.
- `GET /web/demo-analysis` is public and uses bundled synthetic mock evidence.
- `POST /web/team-nebius-demo` is team-only and may invoke the real model.

## Important interpretation rules

- `ai.source = "nebius"` alone does not prove inference succeeded: check `status = "completed"`.
- `tests.passed` describes the **original** Dockerfile, which may appropriately fail.
- `tests.proposed_patch.passed` means two layers of **static** review passed, not build/runtime validation.
- `ai.patch_status = "proposed_not_validated"` does not mean the suggested patch was deployed.
- `response.mode = "simulation"` means defensive actions were not performed.

Use [api_contract.md](api_contract.md) as the authority for exact JSON details and HTTP error behavior. Never include API keys or Basic credentials in requests committed to the repository.
