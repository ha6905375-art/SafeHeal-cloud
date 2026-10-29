# SafeHeal Cloud — Free Render hosting (judges demo)

**Do not deploy `webapp.run:app` on the internet.** It is designed for localhost
and intentionally rejects nonlocal clients. Use `webapp.public:app` instead.
The homepage, bundled demo data, **mock analysis**, and anonymized live event
summaries are open to everyone. Real Nebius analysis and private event APIs
require a password. Analyses are throttled per process and hour.

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
     This remains required to protect real AI, even when public pages are open.
   - `AI_MODE=mock` (no Nebius token consumption while preparing).
   - `SAFEHEAL_MAX_ANALYSES_PER_HOUR=8` (optional; default is 8).
9. Deploy and open the resulting URL in an **incognito window**: it must show
   the homepage **without any login popup**. Cached Basic Auth credentials in
   your normal browser can make this hard to verify.
10. Check `/api/health`, homepage, Load demo Dockerfile + logs, mock
    investigation, public anonymized live events, and the harmless test signal.
11. For a *private* team-only test, visit `/web/unlock` and use username
    **demo** plus the configured secret to unlock protected endpoints.

You can alternatively use the included `render.yaml` Blueprint. Add the
password to the Blueprint environment settings before completing deployment.

## Switch to real Nebius inference only when ready

In Render's **Environment** page, add:
- `AI_MODE=live`
- `NEBIUS_API_KEY` = your actual secret API key (server-side only)
- `NEBIUS_MODEL=nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`

Visit `/web/unlock` first and log in as **demo**, then return to the dashboard.
Without private credentials, POST `/api/analyze` returns HTTP 401 when
`AI_MODE=live`; public visitors cannot spend Nebius credits.
Redeploy and perform *one* authorized analysis; verify `ai.source = nebius`.
The website hosting can be free, **but Nebius inference uses your existing
credits and may incur charges depending on the account**. Restrict the
password to judges/team, monitor credits, and set a provider-side spending cap
if available. Do not print or expose the key to browsers.

The simple Basic Auth/password and process-local request limit are suitable
for a short HTTPS-only public mock / private live demo, not a replacement for production auth,
distributed rate limits, audit logs, or a reliable billing cap.

Do not remove the live-mode authentication check. The public mock endpoint
is rate-limited, but the process-local limit resets whenever the server restarts.
A provider-side budget cap is still recommended before using Nebius live.

## Public mock upload 403 from the hosting edge

Some security gateways block multipart Dockerfile uploads that contain
intentional insecure demo secrets or exploitation examples, returning
HTML **403 Blocked** before the backend sees the request.

- Click **Load demo Dockerfile + logs**, then **Start AI Investigation**.
  The site uses `GET /web/demo-analysis` for built-in mock evidence.
  The Python backend loads its bundled fixture files directly, so the
  browser does not upload those suspicious example strings to the edge.
- This endpoint runs only if `AI_MODE=mock`; it is disabled in live mode
  **even for private authenticated users**.
- Custom files continue to use `POST /api/analyze`, and a hosting security
  gateway can still block uploads. The site now gives a readable error
  in that case; do not disable hosting protections for public uploads.
- Results from the bundled server-side case may have a different event
  count than the currently selected extended scenario in the dashboard.

## Optional private live Nebius demo while keeping public mock

For the actual online NVIDIA/Nebius showcase, keep `AI_MODE=mock` so the
public website continues to work with no credentials or paid inference.

In Render > Environment add these server-side variables:
- `NEBIUS_API_KEY` = your existing secret key (never put it in GitHub or JavaScript)
- `NEBIUS_MODEL=nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`
- `SAFEHEAL_ALLOW_LIVE_DEMO=true` (explicit opt-in; enables the team-only route)
- `SAFEHEAL_MAX_LIVE_ANALYSES_PER_HOUR=2` (optional; per-worker only, **not** a billing cap)

Before testing, confirm your Nebius account has sufficient credits and set
a provider-side budget cap if available.

Open `https://safeheal-cloud.onrender.com/web/unlock` and sign in using
username `demo` and your private password, then return to AI Investigation.
Choose **Team only: run real Nemotron** and explicitly confirm. The request
is a password-protected POST with *no user-uploaded body*, and the server
loads only its fixed synthetic evidence. This reduces false 403 blocks
from security gateways on the intentional insecure Dockerfile strings.

The ordinary **Start AI investigation** button remains public and mock.
The two analysis modes do not mutate global `AI_MODE`; their results share
the same dashboard and static patch review layout.

Only the private Nebius button consumes credits. The local in-memory
rate limit is not persistent across server restarts; keep the password
private and control billing on the provider side.
