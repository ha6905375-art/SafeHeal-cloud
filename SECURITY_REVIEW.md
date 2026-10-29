# SafeHeal Cloud — Security Scan Results and Interpretation

This is a hackathon prototype; these checks do **not** constitute a penetration test or a guarantee of production safety. The public Render service runs on Render's Python runtime, **not** the optional local `Dockerfile.web` image.

## What was checked

The separate [Security audit workflow](.github/workflows/security-audit.yml) runs three tools:

1. **pip-audit:** analyzes the declared Python runtime dependencies and resolved dependency tree for known advisories.
2. **Trivy:** analyzes the *built website demo image* (OS and Python dependency vulnerabilities). It does **not** build or scan an AI-generated proposed Dockerfile.
3. **Gitleaks:** scans the Git checkout/history for potential credentials. This is pattern-based and cannot prove that all past disclosures are absent. Rotate/revoke any exposed credential rather than assuming Git branch deletion erases it.

The initial run of October 29, 2026 reported **0 known advisories in pip-audit** and **no matches in Gitleaks** (at the time of that scan). Trivy reported **44 HIGH Debian 13 OS findings and two HIGH vendored setuptools dependency findings** for the original `python:3.11-slim` image. A temporary `python:3.11-slim-bookworm` experiment had **59 HIGH and 2 CRITICAL OS findings** and was reverted; it was not deployed. Removing unneeded packaging/build modules is being tested as a mitigation for the two Python findings. The **OS findings remain open pending a reviewed base-image update**.

## What this means

- A security scanner flag does **not** necessarily indicate a remotely exploitable vulnerability in the actual running app. Risk depends on package presence, code path, privileges, reachability, environment and whether a fix is available.
- Nor does a clean `pip-audit` or Gitleaks result guarantee security.
- The Docker image is an optional mock-only local development/demo target, runs non-root and with reduced runtime capabilities in Compose. The deployed Render app does not use it.
- No proposed model-generated Dockerfile is built/executed by SafeHeal. Static checks reject common dangerous patterns, but cannot validate runtime behavior.
- **Before using the image in production**, investigate the scanner's open OS findings, assess exploitability, update or remove affected packages as appropriate, and rerun the scans. Do not suppress the audit solely to turn checks green.
- **Real uploaded production evidence remains out of scope** for the hosted Nemotron demo. Pre-inference masking covers known Dockerfile credential assignments and some log fields, not every possible secret format. Never send actual credentials to external inference.

## Review process

Check the latest [GitHub Actions Security audit runs](https://github.com/ywnu/SafeHeal-Cloud/actions/workflows/security-audit.yml). Investigate the Trivy details and classify affected packages as fixed / unfixable / not reachable / needs mitigation, with evidence for each accepted risk. Re-run after base image or app dependency updates.

Do not publish model precision/recall/F1 values without independently reviewing the annotated benchmark data. See `ai/benchmark.py` for synthetic category-level exploratory measurements only.
