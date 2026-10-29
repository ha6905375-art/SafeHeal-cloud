# SafeHeal Cloud — Render free-hosted demo

**Public site:** https://safeheal-cloud.onrender.com  
**GitHub deployment branch:** `feature/render-deployment`  
**App entry point:** `webapp.public:app`. **Never expose `webapp.run:app` to the internet**; it is localhost-only.

## Setup on Render

Create a **Web Service** connected to `ywnu/SafeHeal-Cloud` and choose:

| Setting | Value |
|---|---|
| Name | `safeheal-cloud` (if the name is available) |
| Runtime | Python 3 |
| Branch | `feature/render-deployment` |
| Region | Frankfurt |
| Root Directory | Empty |
| Compute | **Free ($0/month)** |
| Build Command | `pip install -r backend/requirements.txt` |
| Start Command | `uvicorn webapp.public:app --host 0.0.0.0 --port $PORT` |
| Health Check | `/api/health` (if configured) |

### Environment variables (server-side only)

| Variable | Value / note |
|---|---|
| `PYTHON_VERSION` | `3.11.11` |
| `AI_MODE` | **`mock` — keep this value for the public website** |
| `SAFEHEAL_DEMO_PASSWORD` | Unique private password of at least 12 characters (required at startup) |
| `SAFEHEAL_DEMO_USERNAME` | Optional, defaults to `demo` |
| `NEBIUS_API_KEY` | Secret API key; needed for private real AI only |
| `NEBIUS_MODEL` | `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` |
| `SAFEHEAL_ALLOW_LIVE_DEMO` | `true` only when the team wants to enable private real inference |
| `SAFEHEAL_MAX_ANALYSES_PER_HOUR` | Optional public/mock cap; default 40/hour in mock mode |
| `SAFEHEAL_MAX_LIVE_ANALYSES_PER_HOUR` | Optional private live cap; default 2/hour |

These limits are **in-memory and per process**; they are not billing guarantees. Rotate exposed secrets, keep all keys out of GitHub and frontend JavaScript, and consider provider-side limits on Nebius credit spending.

## Test the public site (no Nebius credits)

After Render shows **Live**, open the URL in an **incognito window**. It should show the dashboard without login.

1. Go to **AI Investigation**.
2. Select **Load demo Dockerfile + logs**, then **Start AI Investigation**.
3. Check `COMPLETED`, `MOCK · ANALYZED`, findings, correlations and separate static reviews.
4. Review the other pages and export the synthetic investigation report if desired.

The public demo runs a **server-side** `GET /web/demo-analysis` and does not upload the intentionally risky example through the browser. Hosting-edge protection can still return HTML `403 Blocked` for *custom* multipart uploads to `POST /api/analyze`. Do not bypass hosting security to force uploads.

## Test the real private Nemotron demo

**Keep global `AI_MODE=mock`.** The separate private endpoint forces a real inference for authorized team members while leaving public/mock requests free.

1. Confirm `SAFEHEAL_ALLOW_LIVE_DEMO=true`, `NEBIUS_API_KEY`, `NEBIUS_MODEL` and a strong `SAFEHEAL_DEMO_PASSWORD` in Render.
2. Visit https://safeheal-cloud.onrender.com/web/unlock and sign in using the private credentials (username defaults to `demo`).
3. Return to **AI Investigation**, select **Private Team Access → Run real Nemotron**, and accept the confirmation **once**.
4. Examine `status`, `ai.source` and the **Proposed patch** review independently. A `COMPLETED` model response does not prove its patch is valid.
5. Export the result for internal review. Avoid sharing sensitive values or raw authorization headers.

The private request has **no browser-uploaded Dockerfile body**; the server loads bundled synthetic examples directly. Real inference can **consume Nebius credits**. The per-process two-calls/hour default is *not* a provider-side spending cap.

## Hosting constraints and verification

The Free instance may **sleep after inactivity**, which can delay the first request. The event queue resets on restart; the public feed redacts IP addresses and endpoints.

Direct runtime dependencies in `backend/requirements.txt` and test tools in `requirements-dev.txt` are pinned to previously passing CI versions. GitHub Actions checks clean installs on Ubuntu **and Windows**, and verifies dependency compatibility with `python -m pip check` before the offline tests. Transitive packages remain resolver-selected (not a full hashed lockfile).

GitHub Actions runs offline with `AI_MODE=mock`. On October 29, 2026, **401 tests passed, 2 skipped, 1 warning**. Manual browser tests confirmed both the public mock and a private real Nemotron call. A real reply initially included malformed escaped Dockerfile line breaks; the conflicting static PASS display was fixed in code and regression-tested, but **the originally exported live patch should not be described as passing**.

No proposed Dockerfile has been built or run, no patch was applied, and no real firewall blocking was performed. HTTP Basic and process-local limits are intended for a short hackathon demo, not production use.

See [README.md](README.md) and [contracts/api_contract.md](contracts/api_contract.md) for project and API details.

## Optional local Docker Compose verification

`Dockerfile.web` and `compose.yaml` are for **local mock-only** verification, not Render (which still uses `uvicorn webapp.public:app` directly). Bindings are restricted to `127.0.0.1:8000`, and the app runs as an unprivileged user with a read-only root filesystem and dropped capabilities. Set a private `SAFEHEAL_DEMO_PASSWORD` in your shell, then `docker compose up --build -d`; visit http://127.0.0.1:8000 . Run `docker compose down` afterward. **Never inject real Nebius API keys into this local Compose configuration.**

GitHub Actions also runs an isolated **Chromium** browser flow and an isolated **Docker Compose** health/mock smoke test without Nebius; these jobs do not build or run model-proposed patches.
