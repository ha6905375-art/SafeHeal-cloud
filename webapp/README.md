# Webapp — Frontend and Public Demo

This folder contains the working SafeHeal Cloud browser dashboard and the FastAPI website entry points. The legacy `frontend/` folder is not the active interface.

## What it does

- Displays Overview, AI Investigation, Docker Security, Threat Monitoring, Live Attack Feed, Reports and Settings.
- Loads a bundled vulnerable Dockerfile with synthetic attack logs for a repeatable demo.
- Shows findings, log correlations, a proposed Dockerfile, diff and independent static validation.
- Exports the investigation report as JSON and the proposed patch for inspection; neither is executed.
- Shows a sanitized, limited HTTP suspicious-path feed, not a full SIEM.
- Offers a separate team-only real Nemotron demo; public analysis remains mock-only.
- Automatically retries backend health checks after a slow Render cold start or brief interruption, with bounded backoff and a visible reconnecting indicator; it never starts a paid Nemotron request automatically.

## Main files

| File | Role |
| --- | --- |
| `index.html` | Page structure and user interface elements |
| `styles.css` | Dashboard styles and responsive layout |
| `app.js` | Navigation, API requests, findings rendering and downloads |
| `public.py` | Render-facing website: public mock, Basic-authenticated private team access, rate limits, anonymized events |
| `run.py` | Localhost-only website entry point; do not expose publicly |
| `test_public_demo.py` | Offline access-control, endpoint and UI asset tests |

## How it connects

The UI requests `GET /web/demo-analysis` for server-side bundled mock evidence or `POST /api/analyze` for user-provided Dockerfile and optional logs. The gateway delegates analysis to the backend and AI services. The private `POST /web/team-nebius-demo` requires Basic authentication, explicit server opt-in and server-side Nebius configuration; it is not available anonymously.

The website must remain `AI_MODE=mock` on public Render. Do **not** store the Nebius key or team password in JavaScript, HTML or Git. Custom uploads may be stopped by a hosting gateway.

## Judge-only real inference

For hackathon judging, configure a **different** `SAFEHEAL_JUDGE_USERNAME` and `SAFEHEAL_JUDGE_PASSWORD` (16+ characters) server-side, alongside the protected Nebius runtime configuration. Judge credentials are scoped to `/web/unlock` and `/web/team-nebius-demo` only. They cannot access protected telemetry or unrelated backend routes. Public access remains mock-only and free. See [judging guide](../JUDGING_ACCESS.md). Never commit credentials or expose them in the browser code; per-process throttling does not cap costs.

## Run and test

From the repository root, install `requirements-dev.txt` using Python 3.11, copy `.env.example` to a private `.env`, set `AI_MODE=mock`, and run:

```powershell
py -m uvicorn webapp.run:app --host 127.0.0.1 --port 8000
py -m pytest webapp/test_public_demo.py -q
```

The Render deployment entry point and its required environment settings are in [DEPLOY_RENDER.md](../DEPLOY_RENDER.md). The [browser E2E test](../e2e/README.md) exercises the public mock workflow.

## Limitations

Real traffic is not blocked, suggested patches are not deployed, public event data is anonymized and process-local limits are not a spending cap. UI browser coverage is a smoke test, not a full accessibility certification.
