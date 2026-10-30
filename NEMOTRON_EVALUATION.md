# Nemotron — Safe Synthetic Evaluation Guide

This guide evaluates **actual Nebius-hosted Nemotron model inference** with manually annotated synthetic Dockerfiles and security events. Results are exploratory **category-level proxy** measurements (not independent production precision/recall/F1). The public hosted demo stays mock-only; the judge-only live route remains fixed to bundled synthetic evidence.

## What is measured

`ai/benchmark.py` includes **12 labeled cases** covering:
- a safe Dockerfile without events
- missing non-root USER, and explicit root
- exposed SSH and matching port scans
- hardcoded synthetic token, debug enabled, and a mixed-vulnerability example
- end-of-life Python base, world-writable permissions
- unrelated scans and exploitation attempts, plus wrong-port scan evidence

Two independent scores are shown: (1) micro category precision/recall/F1 for Dockerfile findings and (2) event/source-IP correlation precision/recall/F1 for matching vs unrelated synthetic logs. The report also shows the completed/attempted count, benign-case false-positive rate, per-case expected/predicted categories, patch static status and returned token counts.

**Limitations:** Title keyword matching can misclassify synonyms; human review is essential. A model can be right for the wrong reason or wrong for the right reason. Some fixture scenarios have only one valid interpretation; there is no statistical confidence interval or reproducibility claim. Correlations are not evidence of a successful compromise. Static patch PASS does not mean the generated image builds, runs, or is secure. Failed API requests do not enter F1; use `completion_rate` separately. A real-model score must never be represented as broad real-world accuracy.

## Preparation on a trusted Windows computer

1. Update the **private local clone** from GitHub `main`: `git pull origin main`.
2. Create/use your local `.venv` with Python 3.11. Install the runtime dependencies: `.\.venv\Scripts\python.exe -m pip install -r backend/requirements.txt`.
3. Put `NEBIUS_API_KEY` and the **exact** `NEBIUS_MODEL` used by the team into a private repository-root `.env` file (the file is already ignored by Git). Never place either value in screenshots, chat, public issue comments or CI secrets for this benchmark. Do not copy keys into source code.
4. Ensure the Nebius account has enough credit and appropriate provider-side spending controls; **this script does not cap your account bill**. A model call may consume output tokens even if parsing eventually fails.

## Step A — no-credit check (always first)

Run in the repository-root PowerShell terminal:

```powershell
.\.venv\Scripts\python.exe -m ai.benchmark --output benchmark-mock.json
```

Verify `mode: "mock"`, 12 attempts, no errors and the expected fields. This tests the local scoring pipeline only; **mock results are not Nemotron accuracy**.

## Step B — actual paid inference (explicitly opt in)

Only after reviewing the cases and checking your available credits:

```powershell
$env:SAFEHEAL_BENCHMARK_LIVE = "YES"
.\.venv\Scripts\python.exe -m ai.benchmark --live --max-cases 8 --output benchmark-live.json
Remove-Item Env:SAFEHEAL_BENCHMARK_LIVE
```

- This example runs **at most 8 selected cases** (the first eight) through the same `ai.service.analyze_evidence` flow the application uses, with **no automatic request retries**. It may incur Nebius charges and may take time.
- Use `--max-cases 12` **only if** the team explicitly wants all twelve paid calls and has sufficient budget. Do not re-run automatically if a request fails.
- `AI_MODE` from local `.env` does not override the explicit mode chosen in the script. Neither mode exposes a new API route or changes Render's public `AI_MODE=mock`.
- The report contains only category labels, counts, aggregate token usage and static-review booleans, not Dockerfile contents or secrets. Results are ignored by Git under `benchmark-*.json`.

## Review before quoting the results

1. Check `mode=live` and `ai_source=nebius` on every completed case.
2. Check that `completed=attempted`; if not, document every error code and avoid claiming that F1 covers failed samples.
3. Review the `expected` and `predicted` labels case-by-case. Have another team member review disagreements against the fixture Dockerfile and corresponding event logs.
4. Pay particular attention to **safe and unrelated-log cases**. Unsupported correlations are false positives and should not be described as confirmed attacks.
5. Record `usage.prompt_tokens`, `usage.completion_tokens` and `usage.total_tokens`, then compare with the Nebius usage/billing dashboard to establish actual cost.
6. In Devpost and the video, write **“synthetic, category-level evaluation (N cases)”** and provide the numerator/denominator; never claim production accuracy or that generated Dockerfiles were executed.

If you cannot access a private local Nebius key safely, **do not run the live benchmark**. The hosted `/web/team-nebius-demo` uses a fixed bundled scenario and therefore cannot supply the varied cases needed for this evaluation without a separate safe testing environment. Do not weaken public authorization to get around this.
