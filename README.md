# SafeHeal Cloud — Explainable AI Cyber Defense

**SafeHeal Cloud** is a hackathon prototype that analyzes Dockerfile configuration together with security logs, explains relevant threats, proposes a safer Dockerfile, and performs independent **static** reviews. It never executes proposed changes or blocks real traffic.

**Public demo:** https://safeheal-cloud.onrender.com  
**API contract:** [contracts/api_contract.md](contracts/api_contract.md)  
**Render deployment:** [DEPLOY_RENDER.md](DEPLOY_RENDER.md)

> **Demonstration, not production security software.** Bundled attack events are synthetic, all response actions are simulated, and proposed fixes are not built or applied.

## At a glance

**Problem:** Security teams must interpret configuration risks and suspicious events across different sources. A recommendation is not useful unless its evidence and safety limits are clear.

**Approach:** SafeHeal Cloud combines deterministic checks with evidence-grounded AI investigation and an independent static review of proposed Dockerfile changes. The public demo uses mock analysis; a separately authenticated team-only path demonstrates real Nemotron inference.

**Workflow:** Dockerfile + security logs → findings and event correlations → proposed Dockerfile + diff → independent static checks → downloadable report. All defensive responses remain simulations; no proposed patch is deployed.

**Try it:** [Open the public demo](https://safeheal-cloud.onrender.com), choose **AI Investigation**, load the bundled demo evidence, and start the investigation. No account or API key is needed for the public workflow.

## What the website does

The live dashboard is implemented in **`webapp/`**. Its pages include Overview, AI Investigation, Docker Security, Threat Monitoring, Live Attack Feed, Reports, and Settings.

The **public demo is free and requires no login**:

1. Open the website and select **AI Investigation**.
2. Click **Load demo Dockerfile + logs** and then **Start AI Investigation**.
3. Review evidence-grounded findings, security-event correlations, the proposed Dockerfile patch, its diff, and the original/patch static checks.
4. Export a JSON investigation report or proposed Dockerfile if desired.

**Public results use `AI_MODE=mock`**, a rule-based test pipeline. They are not presented as real Nemotron reasoning. The bundled demonstration runs via `GET /web/demo-analysis`, where the server loads the synthetic evidence directly; this avoids HTML `403 Blocked` responses sometimes returned by hosting security gateways for intentionally dangerous-looking multipart uploads.

**Custom uploads** use `POST /api/analyze` with a file named `Dockerfile` and optional JSON logs. Hosting-edge protection can still block some uploads.

The **Threat Monitoring** scenarios are synthetic fixtures. The **Live Attack Feed** observes only selected suspicious HTTP paths reaching the app; its anonymous feed redacts client IPs and request paths. It is not a network-wide sensor or persistent SIEM.

## Private real AI demonstration

The separate **Private Team Access → Run real Nemotron** button invokes NVIDIA Nemotron through the **Nebius Token Factory** API.

- The deployed public website **stays on `AI_MODE=mock`**, even while team-only inference is enabled.
- The private route `POST /web/team-nebius-demo` requires HTTP Basic authentication, `SAFEHEAL_ALLOW_LIVE_DEMO=true`, and server-side `NEBIUS_API_KEY` and `NEBIUS_MODEL`.
- The team first visits `/web/unlock` to authenticate, returns to AI Investigation, and confirms the private run. The private request uses only **bundled synthetic evidence** and sends no user-uploaded Dockerfile through the browser.
- Real calls consume Nebius credits. The per-process rate limit (default two calls per hour) is **not** a billing cap; use provider-side spending controls when available.

A real inference call was successfully completed on the hosted website on **October 29, 2026** (`ai.source: "nebius"`). Its output also revealed a malformed Dockerfile line-break issue: **completed inference does not guarantee a valid proposed patch**. The static review inconsistency has since been corrected in code and regression-tested, without claiming that the originally exported patch passed.

## Architecture

| Path | Purpose |
|---|---|
| `webapp/index.html`, `styles.css`, `app.js` | Browser UI, scenarios, visualizations, report downloads |
| `webapp/public.py` | Internet-facing FastAPI entry point: public mock, authentication, private Nemotron route, anonymized live events, rate limits |
| `webapp/run.py` | Localhost-only website; **never expose directly to the internet** |
| `backend/main.py` | Health and upload analysis endpoints; backend-owned checks and simulated response |
| `backend/attack_monitor.py` | Classic/extended synthetic event scenarios |
| `backend/live_monitor.py`, `live_events.py`, `live_stream.py` | Limited in-memory suspicious-path observation and protected raw event API |
| `backend/validator.py` and `ai/patch_review.py` | Complementary static Dockerfile reviews |
| `ai/` | Nemotron client, prompts, parser, schema validation, mock inference, evidence grounding, evaluator, tests |
| `security/` | Intentionally vulnerable example Dockerfile and fictional attack events |
| `contracts/` | API contract and example JSON result |
| `.github/workflows/ci.yml` | Offline test suite on GitHub Actions |

The legacy `frontend/` folder is a placeholder; **the working frontend is in `webapp/`**.

### Component documentation

- [Frontend and website — `webapp/`](webapp/README.md)
- [Backend API — `backend/`](backend/README.md)
- [AI and Nemotron — `ai/`](ai/README.md)
- [Security examples and validation — `security/`](security/README.md)
- [API contracts — `contracts/`](contracts/README.md)
- [Chromium E2E tests — `e2e/`](e2e/README.md)

These READMEs document the implementation by **technical component**, not by team member.

### Trust and validation boundaries

- Dockerfile and logs are treated as **untrusted data**. The prompt comes from `ai/prompts/security_agent.txt` and `ai/prompts/docker_patch_rules.txt` plus integration rules in `ai/prompts.py`.
- AI findings are normalized and checked against `ai/output_schema.json`; correlation event types and IPs must be present in supplied logs, and sensitive values are redacted.
- `tests.passed` describes the **original Dockerfile**. A vulnerable original returning `false` is expected.
- `tests.proposed_patch.passed` requires **both** backend and AI-layer static reviews to pass. `ai.patch_review` is the AI-layer review separately. `ai.patch_status = "proposed_not_validated"` means static checks passed, **not** Docker build or runtime validation.
- `response.mode = "simulation"` and actions such as `block_ip` are **never executed**.

## Run locally (Windows PowerShell)

Python **3.11** is recommended.

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
Copy-Item .env.example .env
```

Keep `.env` private and set `AI_MODE=mock` for offline, no-credit tests. For local real-model work, configure `NEBIUS_API_KEY` and `NEBIUS_MODEL` in `.env`; never expose secrets in Git or the browser.

**Start the localhost website:**

```powershell
.\.venv\Scripts\python.exe -m uvicorn webapp.run:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000 . The local live-event gateway additionally needs `LIVE_EVENTS_API_TOKEN` in `.env`.

**Or run the API on its own** (stop the website server first, since both use port 8000):

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Backend-only API docs: http://127.0.0.1:8000/docs . To test the vulnerable sample:

```powershell
curl.exe -sS -X POST "http://127.0.0.1:8000/api/analyze" `
  -F "dockerfile=@security/vulnerable.Dockerfile;filename=Dockerfile" `
  -F "attack_logs=@security/attack_logs.json;type=application/json"
```

**Do not change the publicly deployed service to `AI_MODE=live`**. Use the private team route to test real inference while keeping the anonymous demo free.

## Tests and verified results

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

GitHub Actions installs the requirements from scratch on **Ubuntu and Windows (Python 3.11)**, runs `python -m pip check`, then runs tests offline with `AI_MODE=mock`. The verified October 29, 2026 CI run passed on **both Ubuntu and Windows: 401 passed, 2 skipped, 1 warning** per Python test job. The public mock site and private Nebius route were also exercised manually in a browser. CI additionally runs a **real headless Chromium browser E2E** for public mock analysis, report download and private-route authentication (no Nebius credits). A separate Docker Compose smoke job builds the **demo server image** and probes health/mock routes. Neither job executes AI-proposed patches.

The AI evaluator can be run in mock mode without credits:

```powershell
.\.venv\Scripts\python.exe ai/evaluate.py --run mock
```

Any explicit live evaluation or inference may consume Nebius credits.

## Limitations and remaining tasks

- **No Docker build/runtime validation**; even a static PASS does not prove file permissions or application behavior.
- **No real IP blocking** or automated patch application.
- **Synthetic attack scenarios**, plus a narrow suspicious-HTTP-path observer with a maximum of 200 in-memory events (reset on restart).
- **Free Render may sleep** after inactivity; the first request after sleep can be slower.
- Process-local request throttling and HTTP Basic credentials are demo safeguards, not production-grade authentication, durable audit logging, or spending limits.
- Hosting security may reject some custom uploads containing intentionally exploit-like examples.
- **Direct Python runtime and test dependencies are pinned** to versions exercised in GitHub CI (Python 3.11); transitive packages are still resolver-selected (not a full hash-locked environment). Browser E2E and **demo service image** Docker Compose smoke checks are included in CI; building or running the **AI-proposed patch image** remains out of scope. The browser E2E covers the critical public workflow, not all UI/assistive-technology combinations.

## Optional local Docker Compose demo

The included `Dockerfile.web` and `compose.yaml` **build only the SafeHeal website**, not any AI-generated patch. They start the **mock-only** service on the local loopback interface (`127.0.0.1:8000`) and create an unprivileged application user. The app container has dropped Linux capabilities, a read-only root filesystem and no Nebius token.

On Windows PowerShell, with Docker Desktop running, set a unique password **locally in your shell**:

```powershell
$env:SAFEHEAL_DEMO_PASSWORD = "replace-with-your-own-strong-unique-password"
docker compose up --build -d
```

Open http://127.0.0.1:8000 . The public mock demo needs no browser login. To stop: `docker compose down`. **Do not put an actual Nebius key into Compose**; real inference remains disabled here by default. The development-only Compose password is not committed to source control. CI verifies Compose startup, health, public mock analysis, and refusal of unauthorized private access.

To repeat the **real Chromium browser E2E** locally (Python 3.11 and Chromium required), run:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-e2e.txt
.\.venv\Scripts\python.exe -m playwright install chromium
.\.venv\Scripts\python.exe e2e/browser_smoke.py
```

This starts a temporary local mock web server, checks the browser flow and downloaded JSON, and shuts it down. It never uses Nebius credits.
