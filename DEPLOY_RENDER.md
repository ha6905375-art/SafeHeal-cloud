# SafeHeal Cloud — Free Render hosting (judges demo)

**Do not deploy `webapp.run:app` on the internet.** It is designed for localhost
and intentionally rejects nonlocal clients. Use `webapp.public:app` instead.
This public entrypoint requires a password for the *entire* demo (including
analyze and live feed) and throttles the number of analyses per hour.

## Free hosting and URL

Render's Free web service hosts FastAPI plus the frontend under **one URL**.
Choose the service name `safeheal-cloud`; the URL will usually be
`https://safeheal-cloud.onrender.com` *if available*. Render may require
another name if it is already registered. No purchased domain is needed.

Free Render services sleep after about 15 minutes without traffic, and the
next visit can take a minute to wake them up. The in-memory live events reset
when the service restarts. This is a hackathon demo, not persistent monitoring.

## Deploy from GitHub

1. Sign in to https://dashboard.render.com with GitHub.
2. Choose **New → Web Service**, connect `ywnu/SafeHeal-Cloud`.
3. Choose branch `feature/render-deployment` (or the reviewed merge target).
4. Set **Name** to `safeheal-cloud`, **Language** to Python 3, **Instance** to Free.
5. Set **Build command** to `pip install -r backend/requirements.txt`.
6. Set **Start command** to
   `uvicorn webapp.public:app --host 0.0.0.0 --port $PORT`.
7. Set **Health check path** to `/api/health`.
8. Add environment variables:
   - `PYTHON_VERSION=3.11.11`
   - `SAFEHEAL_DEMO_PASSWORD` = a unique strong secret of at least 12 characters,
     entered in Render's secret environment variables, never committed to Git.
   - `AI_MODE=mock` (no Nebius token consumption while preparing).
   - `SAFEHEAL_MAX_ANALYSES_PER_HOUR=8` (optional; default is 8).
9. Deploy and open the resulting URL. The browser will ask for HTTP Basic
   credentials: username **demo**, password the secret configured above.
10. Check `/api/health`, homepage, Load demo Dockerfile + logs, offline
    investigation, and live test signal.

You can alternatively use the included `render.yaml` Blueprint. Add the
password to the Blueprint environment settings before completing deployment.

## Switch to real Nebius inference only when ready

In Render's **Environment** page, add:
- `AI_MODE=live`
- `NEBIUS_API_KEY` = your actual secret API key (server-side only)
- `NEBIUS_MODEL=nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`

Redeploy and perform *one* analysis; verify `ai.source = nebius`.
The website hosting can be free, **but Nebius inference uses your existing
credits and may incur charges depending on the account**. Restrict the
password to judges/team, monitor credits, and set a provider-side spending cap
if available. Do not print or expose the key to browsers.

The simple Basic Auth/password and process-local request limit are suitable
for a short HTTPS-only private demo, not a replacement for production auth,
distributed rate limits, audit logs, or a reliable billing cap.

If the dashboard is exposed without authentication, its analyze endpoint
could be used to spend credits. Never remove this access control just to
make the demo publicly clickable.
