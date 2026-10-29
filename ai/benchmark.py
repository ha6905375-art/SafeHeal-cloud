"""Small evidence-grounded benchmark; default mode makes NO network calls.

These are category-level PROXY precision/recall/F1 values against manually
selected synthetic Dockerfile cases. They are NOT independently validated
production precision or recall and do not measure all model hallucinations.
Live mode requires BOTH --live and SAFEHEAL_BENCHMARK_LIVE=YES (spends credits).
"""
from __future__ import annotations

import argparse
from dataclasses import replace
import json
import os
import re

from ai.config import get_settings
from ai.service import analyze_evidence

SAFE_HEADER = (
    "FROM python:3.11-slim\n"
    "RUN useradd --create-home appuser\n"
    "USER appuser\n"
)
SAFE_TAIL = 'EXPOSE 8000\nCMD ["python", "app.py"]\n'

CASES = [
    ("safe_no_attack", SAFE_HEADER + SAFE_TAIL, [], set()),
    ("root_only", "FROM python:3.11-slim\n" + SAFE_TAIL, [], {"root"}),
    ("ssh_only", SAFE_HEADER + "EXPOSE 22\n" + SAFE_TAIL,
     [{"event_type": "PORT_SCAN", "source_ip": "192.0.2.10", "target_port": 22}],
     {"ssh"}),
    ("secret_only", SAFE_HEADER + "ENV API_TOKEN=BENCHMARK_FAKE_VALUE\n" + SAFE_TAIL,
     [], {"secret"}),
    ("debug_only", SAFE_HEADER + "ENV DEBUG_MODE=true\n" + SAFE_TAIL,
     [], {"debug"}),
    ("safe_unrelated_logs", SAFE_HEADER + SAFE_TAIL,
     [{"event_type": "PORT_SCAN", "source_ip": "192.0.2.11", "target_port": 22}],
     set()),
]

CATEGORIES = {
    "root": re.compile(r"(?i)\b(root|non-root|USER directive|runs as root)\b"),
    "ssh": re.compile(r"(?i)\b(ssh|openssh|port 22)\b"),
    "secret": re.compile(r"(?i)\b(secret|hardcoded|hard-coded|credential|api[_ -]?token|api[_ -]?key)\b"),
    "debug": re.compile(r"(?i)\b(debug|DEBUG_MODE)\b"),
}


def categories(findings):
    predicted = set()
    unknown = 0
    for f in findings:
        if not isinstance(f, dict):
            continue
        message = " ".join(str(f.get(k, "")) for k in ("title", "description"))
        matched = {key for key, pattern in CATEGORIES.items() if pattern.search(message)}
        if matched:
            predicted.update(matched)
        else:
            unknown += 1
    return predicted, unknown


def metrics(tp, fp, fn):
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    return {"precision": round(precision, 4),
            "recall": round(recall, 4), "f1": round(f1, 4)}


def benchmark(mode="mock"):
    settings = replace(get_settings(), mode=mode)
    report = {"mode": mode, "metric_scope": "synthetic, category-level proxy; not production accuracy",
              "cases": [], "tp": 0, "fp": 0, "fn": 0,
              "unmapped_findings": 0, "errors": 0}
    for name, docker, logs, expected in CASES:
        result = analyze_evidence(docker, logs, settings=settings)
        if result["status"] != "completed":
            report["errors"] += 1
            report["cases"].append({"name": name, "status": "ai_error"})
            continue
        predicted, unmapped = categories(result.get("findings", []))
        tp = len(expected & predicted)
        fp = len(predicted - expected) + unmapped
        fn = len(expected - predicted)
        report["tp"] += tp
        report["fp"] += fp
        report["fn"] += fn
        report["unmapped_findings"] += unmapped
        report["cases"].append({"name": name, "status": result["status"],
                                "expected": sorted(expected),
                                "predicted": sorted(predicted),
                                "tp": tp, "fp": fp, "fn": fn,
                                "unmapped_findings": unmapped,
                                "correlations": len(result.get("correlations", []))})
    report.update(metrics(report["tp"], report["fp"], report["fn"]))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true",
                        help="make paid Nebius calls; also requires SAFEHEAL_BENCHMARK_LIVE=YES")
    parser.add_argument("--output", help="save aggregate scores as JSON")
    args = parser.parse_args()
    if args.live and os.getenv("SAFEHEAL_BENCHMARK_LIVE") != "YES":
        parser.error("Live benchmark requires SAFEHEAL_BENCHMARK_LIVE=YES and valid Nebius configuration")
    report = benchmark("live" if args.live else "mock")
    print(json.dumps(report, indent=2))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=2)
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
