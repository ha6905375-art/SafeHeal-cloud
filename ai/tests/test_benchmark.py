"""Offline tests of category-level evaluation logic (no paid model calls)."""
from ai.benchmark import CASES, categories, metrics


def test_benchmark_cases_include_benign_and_unrelated_logs():
    names = {case[0] for case in CASES}
    assert len(names) == len(CASES)
    assert {"safe_no_attack", "safe_unrelated_logs", "root_only", "ssh_only", "secret_only", "debug_only"} <= names
    assert not dict((name, expected) for name, _, _, expected in CASES)["safe_no_attack"]


def test_metric_math_reports_precision_recall_f1():
    assert metrics(2, 1, 1) == {"precision": 0.6667, "recall": 0.6667, "f1": 0.6667}
    assert metrics(0, 0, 0) == {"precision": 0.0, "recall": 0.0, "f1": 0.0}


def test_unknown_findings_are_counted_not_silently_dropped():
    predicted, other = categories([
        {"title": "Container runs as root"},
        {"title": "Hardcoded secret"},
        {"title": "Unrecognized synthetic security issue"},
    ])
    assert predicted == {"root", "secret"}
    assert other == 1
