# Autonomous-Cyber-Defense-Agent (SafeHeal-Cloud prototype)

SafeHeal-Cloud analyzes a container's Dockerfile together with its security logs, explains which weaknesses the logged attack activity relates to, and proposes a fix — without ever executing anything the AI suggests.

## The problem

Container misconfigurations (running as root, hardcoded secrets, debug mode left on, unnecessary SSH) are common, and security alerts usually arrive separately from the configuration they relate to. Connecting "this IP is scanning port 22" to "this Dockerfile installs an SSH server" is manual work, and AI tools asked to do it can invent findings or claim fixes that were never tested.

## What it does

`POST /api/analyze` takes a `Dockerfile` and optional attack logs (JSON) and returns one result:

1. **Findings** — security weaknesses in the Dockerfile, with evidence.
2. **Correlations** — which logged events (event type and source IP) relate to which findings.
3. **Proposed patch** — a corrected Dockerfile and a diff computed locally.
4. **Backend checks** — an independent static review of the uploaded Dockerfile and of the proposed patch (`tests`, `tests.proposed_patch`).
5. **Simulated response** — defensive actions such as "block IP" that are only simulated, never executed.

`GET /api/health` returns `{"status": "ok"}`. The response format is documented in `contracts/api_contract.md` and `contracts/example_response.json`.

## Role of the AI

- An NVIDIA Nemotron model is called through the **Nebius Token Factory** API (OpenAI-compatible chat completions); the model is set with `NEBIUS_MODEL`.
- The system prompt is built from the Prompt & Reasoning files `ai/prompts/security_agent.txt` and `ai/prompts/docker_patch_rules.txt`, followed by the integration's safety and output-format rules (`ai/prompts.py`).
- The model produces findings, correlations and the proposed patch. Everything else is code:
  - uploaded files and logs are sent as delimited data, and the model is told not to follow instructions inside them;
  - the reply must be one JSON object; it is parsed, validated against `ai/output_schema.json` (reported as `ai.schema_validation`) and normalized; a malformed reply returns `status: "ai_error"`, never a guess;
  - correlation event types and IPs are kept only if they appear in the uploaded logs;
  - secret values from the Dockerfile and patch are replaced with `[REDACTED]`;
  - the patch is only statically reviewed: escaped line breaks are normalized or rejected, and the final `USER` must be non-root; nothing is built, run or applied;
  - a failed live call is reported as an error; there is no silent fallback to mock results.
- `ai.source` is the configured mode (`nebius` or `mock`). It is `nebius` even when the live call failed, so a genuine model answer is `status: "completed"` with `ai.source: "nebius"` and an `ai.usage` token count.

## Repository layout

| Path | Contents |
|---|---|
| `backend/` | FastAPI app (`main.py`), Dockerfile validator, response simulation, tests |
| `ai/` | Nebius client, prompts and prompt files, response parser, schema check, patch review, offline mock, evaluator, tests — see `ai/README.md` |
| `security/` | Synthetic demo inputs: `vulnerable.Dockerfile`, `attack_logs.json` (dummy secret only) |
| `contracts/` | API contract and example response |
| `frontend/` | README only — **no frontend code exists in this repository** |

## Requirements

- Python **3.10 or newer** (the code uses `X | None` type syntax).
- Runtime packages: `backend/requirements.txt`. Tests and lint: `requirements-dev.txt` (adds `pytest`, `httpx`, `ruff`).
- For live mode only: a Nebius Token Factory API key and model ID. Mock mode needs no key.

## Setup (Windows PowerShell, from the repository root)

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
Copy-Item .env.example .env
```

Edit `.env` (it is gitignored — never commit it):

- `AI_MODE=mock` (default) runs fully offline with a rule-based mock: no key, no cost. Mock results are not real AI analysis.
- For the real model set `AI_MODE=live`, `NEBIUS_API_KEY` and `NEBIUS_MODEL`. `NEBIUS_MAX_OUTPUT_TOKENS` defaults to 16384; at 4096 the Nemotron reply was cut off and rejected.
- If a key appears twice in `.env`, the last value is used. Real environment variables override `.env`.

Check the live configuration without printing the key (`--chat` sends one small request and uses a few tokens):

```powershell
.\.venv\Scripts\python.exe -m ai.check_connection
```

## Run

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

API docs: <http://127.0.0.1:8000/docs>. Analyze the demo inputs (the upload must be named `Dockerfile`):

```powershell
curl.exe -sS -X POST "http://127.0.0.1:8000/api/analyze" `
  -F "dockerfile=@security/vulnerable.Dockerfile;filename=Dockerfile" `
  -F "attack_logs=@security/attack_logs.json;type=application/json"
```

In live mode every analyze request calls Nebius and uses credits.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest backend ai/tests -q
```

The test run is offline by default: the repository-root `conftest.py` forces `AI_MODE=mock` and blocks real Nebius network access, so it uses no credits even when `.env` says `live`. One live test is opt-in and calls Nebius (uses credits): set `RUN_LIVE_TESTS=1` and select it with `-k live_nebius`.

Evaluate the AI output against the Prompt & Reasoning test case:

```powershell
python ai/evaluate.py                                     # saved fixture
.\.venv\Scripts\python.exe ai/evaluate.py --run mock      # offline pipeline (wiring only)
.\.venv\Scripts\python.exe ai/evaluate.py --run live      # real model, uses credits
```

## Verified on this branch

- Offline test suite: **335 passed, 1 skipped** (the opt-in live test), 0 failed.
- `/api/analyze` offline with stub AI clients: a completed analysis, a malformed model reply (`ai_error` / `invalid_response`), a patch that fails static review, and an unreachable AI service (`ai_error` / `network_error`) — the backend's own checks and simulation run in every case.
- Evaluator: 4/4 expected findings on the saved fixture and on the mock pipeline.

## Not verified

- This branch has not been run against the live Nebius model. Live requests were verified on the earlier integration branch and on `test/live-monitor-ai`, which use different prompt code.
- No proposed Dockerfile has been built or run in Docker.
- There is no frontend, so no UI-to-backend test exists.
- Production concerns (authentication, rate limiting, deployment) are not implemented or tested.

## Limitations of this prototype

- Inputs are synthetic demo files; there is no live log source or cloud integration.
- Patch validation is static text checking only. Passing it does not mean a patch is secure or works: file permissions, base-image vulnerabilities and dependencies are not checked, and nothing is built or run.
- Response actions are simulated only; nothing is blocked.
- Model output varies between runs; findings can be missed or worded differently.
- Terraform prompts in `ai/prompts/` are reference material and are not wired into the API.
