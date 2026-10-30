"""Synthetic case-level category and correlation PROXY benchmark for SafeHeal.

Default = local mock, no network or credits. Real Nebius requires:
  SAFEHEAL_BENCHMARK_LIVE=YES python -m ai.benchmark --live --max-cases 8

This is an exploratory, manually labeled *synthetic* benchmark, NOT a verified
production-accuracy estimate. Case labels and classification rules require
manual review before presenting precision, recall, or F1 publicly. We never
build/run model-proposed Dockerfiles or print prompts, secrets, or raw findings.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
import json
import os
import re
from typing import Any

from ai.config import get_settings
from ai.service import analyze_evidence

SAFE_HEADER = (
    "FROM python:3.11-slim\n"
    "RUN useradd --create-home appuser\n"
    "USER appuser\n"
)
SAFE_TAIL = 'EXPOSE 8000\nCMD ["python", "app.py"]\n'

# Hand-annotated Dockerfile categories: no judgment about actual exploit success.
CASES = [
    ("safe_no_attack", SAFE_HEADER + SAFE_TAIL, [], set()),
    ("root_only", "FROM python:3.11-slim\n" + SAFE_TAIL, [], {"root"}),
    ("ssh_only", SAFE_HEADER + "EXPOSE 22\n" + SAFE_TAIL,
     [{"event_type": "PORT_SCAN", "source_ip": "192.0.2.10", "target_port": 22}],
     {"ssh"}),
    ("secret_only", SAFE_HEADER + "ENV API_TOKEN=SYNTHETIC_BENCHMARK_SECRET\n" + SAFE_TAIL,
     [], {"secret"}),
    ("debug_only", SAFE_HEADER + "ENV DEBUG_MODE=true\n" + SAFE_TAIL,
     [], {"debug"}),
    ("safe_unrelated_logs", SAFE_HEADER + SAFE_TAIL,
     [{"event_type": "PORT_SCAN", "source_ip": "192.0.2.11", "target_port": 22}],
     set()),
    ("unsupported_python_base",
     SAFE_HEADER.replace("python:3.11-slim", "python:3.9-slim") + SAFE_TAIL,
     [], {"python_eol"}),
    ("world_writable", SAFE_HEADER + "RUN chmod 777 /app\n" + SAFE_TAIL,
     [], {"permissions"}),
    ("mixed_attack",
     "FROM python:3.11-slim\nENV API_TOKEN=SYNTHETIC_BENCHMARK_SECRET\n"
     "ENV DEBUG_MODE=true\nRUN apt-get update && apt-get install -y openssh-server\n"
     "EXPOSE 22\n" + SAFE_TAIL,
     [
         {"event_type": "PORT_SCAN", "source_ip": "192.0.2.20", "target_port": 22},
         {"event_type": "AUTH_ATTEMPT", "source_ip": "192.0.2.20", "target_port": 22},
         {"event_type": "EXPLOITATION_ATTEMPT", "source_ip": "192.0.2.20",
          "details": "Attempt to query /api/debug?env=true"},
     ],
     {"root", "ssh", "secret", "debug"}),
    ("safe_unrelated_exploitation", SAFE_HEADER + SAFE_TAIL,
     [{"event_type": "EXPLOITATION_ATTEMPT", "source_ip": "192.0.2.40",
       "details": "Attempted debug endpoint access unrelated to this configuration"}],
     set()),
    ("ssh_scan_wrong_port", SAFE_HEADER + "EXPOSE 22\n" + SAFE_TAIL,
     [{"event_type": "PORT_SCAN", "source_ip": "192.0.2.30", "target_port": 443}],
     {"ssh"}),
    ("explicit_root", "FROM python:3.11-slim\nUSER root\n" + SAFE_TAIL,
     [], {"root"}),
]

# Correlation ground truth is a judgment about whether logs plausibly relate
# to a configuration issue. It is NOT proof an attacker succeeded.
EXPECTED_EVENT_PAIRS = {
    "ssh_only": {("PORT_SCAN", "192.0.2.10")},
    "mixed_attack": {
        ("PORT_SCAN", "192.0.2.20"),
        ("AUTH_ATTEMPT", "192.0.2.20"),
        ("EXPLOITATION_ATTEMPT", "192.0.2.20"),
    },
}

# These proxy categories are classified from finding titles only. Synonym
# gaps and multi-topic titles can change scores; inspect per-case labels.
CATEGORIES = {
    "root": re.compile(r"(?i)\b(root|non-root|privileged user|missing user)\b"),
    "ssh": re.compile(r"(?i)\b(ssh|openssh|port 22)\b"),
    "secret": re.compile(r"(?i)\b(secret|hardcoded|hard-coded|credential|api[_ -]?token|api[_ -]?key|password)\b"),
    "debug": re.compile(r"(?i)\b(debug|debugging)\b"),
    "python_eol": re.compile(r"(?i)\b(unsupported python|outdated python|python\s*3\.(?:9|10)|end.of.life python)\b"),
    "permissions": re.compile(r"(?i)\b(world.writable|chmod\s*777|unsafe file permissions|permissive file permissions)\b"),
}


def categories(findings: Any) -> tuple[set[str], int]:
    """Identify high-level finding categories; count any unclassified findings as FPs."""
    predicted: set[str] = set()
    unknown = 0
    if not isinstance(findings, list):
        return predicted, 0
    for finding in findings:
        if not isinstance(finding, dict):
            unknown += 1
            continue
        title = str(finding.get("title", ""))
        matched = {key for key, pattern in CATEGORIES.items() if pattern.search(title)}
        if matched:
            predicted.update(matched)
        else:
            unknown += 1
    return predicted, unknown


def metrics(tp: int, fp: int, fn: int) -> dict[str, float]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    return {"precision": round(precision, 4),
            "recall": round(recall, 4), "f1": round(f1, 4)}


def _returned_pairs(result: dict) -> set[tuple[str, str]]:
    """Use only event_type and source_ip strings; no log content in the report."""
    return {
        (c["event_type"], c["source_ip"])
        for c in result.get("correlations", [])
        if isinstance(c, dict) and isinstance(c.get("event_type"), str)
        and isinstance(c.get("source_ip"), str)
    }


def benchmark(mode: str = "mock", max_cases: int | None = None) -> dict[str, Any]:
    if mode not in ("mock", "live"):
        raise ValueError("mode must be mock or live")
    if max_cases is not None and not 1 <= max_cases <= len(CASES):
        raise ValueError(f"max_cases must be 1..{len(CASES)}")

    settings = get_settings()
    if mode == "live":
        if os.getenv("SAFEHEAL_BENCHMARK_LIVE") != "YES":
            raise ValueError("Refusing real API calls: set SAFEHEAL_BENCHMARK_LIVE=YES")
        if max_cases is None:
            raise ValueError("Paid mode requires an explicit --max-cases limit")
        if not settings.api_key or not settings.model:
            raise ValueError("NEBIUS_API_KEY and NEBIUS_MODEL must be configured locally")
        # No hidden retries when benchmarking: makes budget planning more predictable.
        settings = replace(settings, mode="live", max_retries=0)
    else:
        settings = replace(settings, mode="mock", api_key="")

    chosen = CASES[:max_cases] if max_cases is not None else CASES
    report: dict[str, Any] = {
        "mode": mode,
        "metric_scope": "manually labeled synthetic categories and event pairs; exploratory proxy NOT production model accuracy",
        "metric_limitations": (
            "Category mapping uses finding titles; ambiguous synonyms and labels need manual review. "
            "Failed cases are excluded from precision/recall/F1; see completion_rate. "
            "Metrics do not prove attack success, Docker build validity or deployed security."
        ),
        "model": settings.model if mode == "live" else "mock-rule-based",
        "cases": [],
        "attempted": len(chosen),
        "completed": 0,
        "errors": 0,
        "tp": 0, "fp": 0, "fn": 0,
        "correlation_tp": 0, "correlation_fp": 0, "correlation_fn": 0,
        "unmapped_findings": 0, "benign_cases_with_false_positive": 0,
        "benign_cases_completed": 0,
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }

    for name, docker, logs, expected in chosen:
        result = analyze_evidence(docker, logs, settings=settings)
        if result.get("status") != "completed":
            report["errors"] += 1
            report["cases"].append({
                "name": name, "status": result.get("status", "error"),
                "error_code": result.get("ai", {}).get("error", {}).get("code", "unknown"),
            })
            continue

        predicted, unmapped = categories(result.get("findings", []))
        tp = len(expected & predicted)
        fp = len(predicted - expected) + unmapped
        fn = len(expected - predicted)

        expected_pairs = EXPECTED_EVENT_PAIRS.get(name, set())
        actual_pairs = _returned_pairs(result)
        ctp = len(expected_pairs & actual_pairs)
        cfp = len(actual_pairs - expected_pairs)
        cfn = len(expected_pairs - actual_pairs)

        report["tp"] += tp
        report["fp"] += fp
        report["fn"] += fn
        report["correlation_tp"] += ctp
        report["correlation_fp"] += cfp
        report["correlation_fn"] += cfn
        report["unmapped_findings"] += unmapped
        report["completed"] += 1

        if not expected:
            report["benign_cases_completed"] += 1
            if predicted or unmapped:
                report["benign_cases_with_false_positive"] += 1

        usage = result.get("ai", {}).get("usage", {})
        if isinstance(usage, dict):
            for field in report["usage"]:
                value = usage.get(field)
                if type(value) is int and value >= 0:
                    report["usage"][field] += value

        report["cases"].append({
            "name": name,
            "status": "completed",
            "expected": sorted(expected),
            "predicted": sorted(predicted),
            "tp": tp, "fp": fp, "fn": fn,
            "unmapped_findings": unmapped,
            "expected_correlations": len(expected_pairs),
            "observed_correlations": len(actual_pairs),
            "correlation_tp": ctp, "correlation_fp": cfp, "correlation_fn": cfn,
            "static_patch_passed": (
                result.get("tests", {}).get("proposed_patch", {}).get("passed")
            ),
            "ai_source": result.get("ai", {}).get("source"),
        })

    report.update(metrics(report["tp"], report["fp"], report["fn"]))
    report["correlation_metrics"] = metrics(
        report["correlation_tp"], report["correlation_fp"], report["correlation_fn"]
    )
    report["completion_rate"] = round(
        report["completed"] / report["attempted"], 4
    ) if report["attempted"] else 0.0
    report["benign_case_false_positive_rate"] = (
        round(report["benign_cases_with_false_positive"] / report["benign_cases_completed"], 4)
        if report["benign_cases_completed"] else None
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true",
                        help="make PAID Nebius calls; requires SAFEHEAL_BENCHMARK_LIVE=YES")
    parser.add_argument("--max-cases", type=int,
                        help=f"run first N of {len(CASES)} cases; REQUIRED for paid mode")
    parser.add_argument("--output", help="save aggregate scores and per-case proxy counts as JSON")
    args = parser.parse_args()
    try:
        report = benchmark("live" if args.live else "mock", args.max_cases)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=2)
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
