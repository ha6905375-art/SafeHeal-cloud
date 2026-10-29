# SafeHeal Cloud — Judge Testing Guide

**Public demo:** https://safeheal-cloud.onrender.com

SafeHeal has two separate flows. The public **AI Investigation → Load demo Dockerfile + logs → Start AI Investigation** runs deterministic **mock** analysis, needs no login, and does not incur Nebius charges. To verify the actual NVIDIA model integration, use the separate **Run real Nemotron** action with judge-only credentials configured by the project team.

## Set up judge-only access (team administrator)

1. Keep `AI_MODE=mock` on Render so anonymous visitors cannot trigger paid inference.
2. In Render's *server-side* environment settings for the existing web service, retain `SAFEHEAL_DEMO_PASSWORD` for team administrators, and configure a **different** `SAFEHEAL_JUDGE_USERNAME` (not the team username, which defaults to `demo`) and a randomly generated `SAFEHEAL_JUDGE_PASSWORD` of at least **16 characters**. Both values must be set together. Never put real values in Git, source code, the HTML, screenshots or this guide.
3. For real inference, also configure the server-side `NEBIUS_API_KEY`, `NEBIUS_MODEL`, and `SAFEHEAL_ALLOW_LIVE_DEMO=true`. The public service remains in mock mode. Confirm these are configured without sharing their values.
4. Decide on and enforce a **provider-side credit/spend allowance** appropriate for judging. `SAFEHEAL_MAX_LIVE_ANALYSES_PER_HOUR` defaults to two calls/hour, shared between team and judges, **per running process**. It is not a hard billing cap and resets on restart. A leaked judge password can still incur Nebius charges until access is disabled or quota is exhausted.
5. Test from a private/incognito browser session after Render redeploys. Visit `https://safeheal-cloud.onrender.com/web/unlock`, enter the **judge** username/password in the browser's Basic Auth prompt, return to the homepage and choose **AI Investigation → Private Team Access → Run real Nemotron**. Confirm the charge warning once.
6. Verify `ai.source = "nebius"` and the displayed findings. **Completed inference does not prove the suggested Dockerfile is valid**; inspect static checks. Judge access is intentionally limited to `GET /web/unlock` and `POST /web/team-nebius-demo`. It cannot read private raw event feeds, API docs or arbitrary private backend routes.

## Information for the Devpost testing instructions (English)

- **Website:** https://safeheal-cloud.onrender.com
- **Anonymous workflow:** AI Investigation → Load demo Dockerfile + logs → Start AI Investigation. Results are marked MOCK.
- **Real-model workflow:** Open https://safeheal-cloud.onrender.com/web/unlock and authenticate using the separately supplied **judge-only** login credentials; return to the dashboard and click **AI Investigation → Private Team Access → Run real Nemotron**. Allow the inference to finish; inspect `ai.source: nebius`, the findings, event correlations, proposed patch and independent static-review status.
- **Input scope:** Both the private live demo and the public mock demo use bundled **synthetic evidence**. Judge access does not allow uploading private Dockerfiles for live AI analysis.
- **Safety limitations:** No proposed Dockerfile is built, deployed or executed; defensive actions are simulations. Real runs use Nebius credits and may be rate-limited.
- **Credential delivery:** The project representative must supply the correct judge-only username/password via Devpost testing instructions in the manner allowed by the platform. Check whether the field is publicly visible before entering credentials; **never use the team admin password or Nebius API key**. If a credential might be exposed publicly, assume anyone could use it and rely on provider-level spending controls, rotation and monitoring.

**Availability:** The official rules require the project to remain accessible for judging until **December 15, 2026**. Ensure hosting, credentials and provider credits remain available through that date. If access is disabled by rate limits, spend limits or expired credentials, judges may not be able to test real inference.

The judge credentials are **not embedded in this repository**. A correct GitHub deployment alone does not enable judge access: the Render environment variables, credits, and completed Devpost instructions must also be in place.
