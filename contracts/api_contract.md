# SafeHeal Cloud API Contract

This document describes the current **`feature/render-deployment`** implementation. The complete example response is in [example_response.json](example_response.json).

**Scope:** Hackathon prototype. Bundled logs are synthetic, Dockerfile validation is **static**, and all proposed defensive actions are **simulated** (no container is built, no patch applied, no real firewall change).

## Entrypoints and authentication

- `backend.main:app` — standalone backend API, suitable for localhost use. Raw live event routes require a Bearer token.
- `webapp.run:app` — **localhost-only** website.
- `webapp.public:app` — public Render site with anonymous mock routes, plus Basic-authenticated private team endpoints. The public site uses `AI_MODE=mock`.

An HTTP 200 response is **not** enough to conclude that inference succeeded: inspect `status` and `ai.source`.

## Health and analysis

### `GET /api/health`

HTTP 200 response: `{"status":"ok"}`. Public on Render.

### `POST /api/analyze`

`multipart/form-data` fields:

| Field | Required | Format |
|---|---|---|
| `dockerfile` | Yes | UTF-8 file whose *uploaded filename* is exactly `Dockerfile` |
| `attack_logs` | No | `.json` filename containing a JSON object or array |

Maximum size: **1 MiB per file**. Invalid file name, empty file, bad UTF-8 or invalid JSON returns HTTP 400; oversized files return 413; missing/invalid multipart fields may produce FastAPI HTTP 422. The service checks inputs before calling the AI.

For valid input, successful analysis (`status: "completed"`) and handled AI errors (`status: "ai_error"`) both use **HTTP 200 JSON**. In a handled AI error, `ai.error` has `code` and `message`, `findings` and `correlations` are empty, patch fields are empty, but original-file validation and simulated response may still be present.

`ai.source` is `mock` for the offline, rule-based pipeline, `nebius` for configured live inference, or `unknown` after an unexpected service failure. Even `source: "nebius"` does not imply success unless `status: "completed"`.

The public site exposes this POST anonymously only while `AI_MODE=mock`. Some hosting security gateways reject suspicious-looking multipart uploads with an HTML **403 Blocked** response before the request reaches FastAPI. Use `GET /web/demo-analysis` for the built-in demo.

### Response object

The JSON structure contains:

| Top-level field | Contents |
|---|---|
| `status` | `completed` or `ai_error` |
| `findings[]` | `id`, `title`, `severity`, `description`, `recommendation` |
| `correlations[]` | `event_type`, `source_ip`, `related_finding_ids[]`, `explanation` |
| `patch` | `patched_dockerfile` (complete proposed text), `diff` (computed locally), `summary` |
| `tests` | Backend-owned original-file check and (when a patch exists) `proposed_patch` |
| `response` | Backend-owned `mode: "simulation"` and `actions[]` |
| `ai` | Model source/name, summary, limitations, next steps, warnings, evidence, patch review/status and errors |

**Distinguish original checks from proposed-patch checks:**

- `tests.passed` / `tests.details` evaluate the **original** Dockerfile. For the intentionally vulnerable example, `passed: false` is expected.
- `tests.proposed_patch` appears for a **nonempty patch**, shaped as `{"status":"static_review_only","passed":true|false,"details":[...]}`.
- `tests.proposed_patch.passed` is **true only when the backend Dockerfile validator AND the AI/evidence-aware patch review both pass**. A failure in either appears in `details`.
- `ai.patch_review` records the narrower AI-layer static review (`type`, `passed`, `issues[]` with codes/messages, `note`). It does **not** replace the combined `tests.proposed_patch` result.
- `ai.patch_status` can be `none`, `proposed_not_validated` (the static reviews passed), or `proposed_failed_static_review`. The first passing label **never means the patch was built or executed**.
- Malformed literal `\n` within Dockerfile instruction text is either safely normalized or reported as a static issue.

**AI metadata:** `ai.summary`, `limitations[]`, `next_steps[]`, `warnings[]`, `finding_evidence` (ID-to-quoted-evidence mapping), `error` (null on success). `ai.schema_validation` reflects `ai/output_schema.json` checking of the raw model response before normalization. Successful live calls may also include `ai.usage` token counts (`prompt_tokens`, `completion_tokens`, `total_tokens`).

**Simulation:** `response.mode` is `simulation`. Actions such as `{"type":"block_ip","target":"198.51.100.45","reason":"port_scan","status":"simulated"}` are illustrative and **never block real traffic**.

## Synthetic threat scenarios

### `GET /api/attack-events?scenario=classic`

Returns `{"mode":"simulation","total":number,"events":[...]}`. The default scenario `classic` loads `security/attack_logs.json`. `scenario=extended` loads the extended fixture `security/attack _logs.json` (the filename really includes a space). Other scenario values return HTTP 422. This route is public on the website.

## Live observed HTTP events

### `GET /api/live-events?after_id=0`

Returns `{"mode":"live","total":number,"events":[...]}` for observed event IDs strictly greater than `after_id`. Requires `Authorization: Bearer <LIVE_EVENTS_API_TOKEN>` on the backend; without token configuration it returns 503, and without valid credentials 401. The public deployment's outer Basic Auth also restricts this **raw** endpoint.

### `GET /api/live-events/stream`

Raw live monitoring via Server-Sent Events (`text/event-stream`), with `id`, `event: attack` and `data` payloads, supporting `Last-Event-ID` plus heartbeat comments. Requires the same Bearer token and the public gateway's additional site authorization.

The in-memory monitor flags only a limited set of suspicious HTTP URL paths (`/.env`, `/.git/`, `/wp-admin`, `/api/debug`, `/actuator/env`). **Maximum 200 entries**, cleared by restarts. It observes, but **does not block**, HTTP requests.

### `GET /web/live-events?after_id=0`

The **public** browser gateway: `{"mode":"live","privacy":"anonymized","total":number,"events":[...]}`. It redacts `source_ip` as `REDACTED` and `endpoint` as `[redacted]`, and sets `action_taken` to `NONE`. It does **not** expose the privileged raw monitoring feed.

`GET /api/debug/demo` is a harmless path-based probe that normally returns 404 while allowing the observer to record a suspicious HTTP path. It is not a real exploit.

## Website demo routes

| Route | Website access | Behavior |
|---|---|---|
| `GET /` | Public | Dashboard HTML |
| `GET /web/assets/app.js` and `/web/assets/styles.css` | Public | Frontend assets |
| `GET /web/demo-dockerfile` | Public | Bundled fictional vulnerable Dockerfile as text |
| `GET /web/demo-analysis` | Public when `AI_MODE=mock` | Complete server-side **mock** investigation with bundled synthetic evidence, no file upload |
| `GET /web/unlock` | **Basic Auth required** | Authenticate team credentials for private endpoints |
| `POST /web/team-nebius-demo` | **Basic Auth required**, feature enabled | Real Nebius inference using *only* server-side fixed demo evidence; can consume credits |

The team route needs `SAFEHEAL_ALLOW_LIVE_DEMO=true`, `NEBIUS_API_KEY` and `NEBIUS_MODEL` in **server environment variables**. It uses an explicit **live** settings object without altering the public site's `AI_MODE=mock`. When disabled or not configured, it returns 503; invalid origin can return 403; the request cap can return 429. If model inference fails after acceptance, the JSON can still be HTTP 200 with `status: "ai_error"`.

Demo request limits are **per process, not persistent**: public mock defaults to **40/hour** (overridden by `SAFEHEAL_MAX_ANALYSES_PER_HOUR`), and private Nebius defaults to **2/hour** (overridden by `SAFEHEAL_MAX_LIVE_ANALYSES_PER_HOUR`). The limits reset at restart and do not guarantee a spending cap.

Do **not** put Nebius keys, Basic passwords, monitoring Bearer tokens, or raw authorization headers in source control or public reports. See [DEPLOY_RENDER.md](../DEPLOY_RENDER.md).
