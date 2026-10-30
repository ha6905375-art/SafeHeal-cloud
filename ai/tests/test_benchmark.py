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


def test_benchmark_includes_mixed_and_negative_correlation_cases():
    from ai.benchmark import EXPECTED_EVENT_PAIRS
    cases = {name: (docker, logs, expected) for name, docker, logs, expected in CASES}
    assert len(cases) >= 10
    assert {"mixed_attack", "unsupported_python_base", "world_writable",
            "safe_unrelated_exploitation", "ssh_scan_wrong_port"} <= cases.keys()
    assert cases["mixed_attack"][2] == {"root", "ssh", "secret", "debug"}
    assert EXPECTED_EVENT_PAIRS["mixed_attack"]
    assert not EXPECTED_EVENT_PAIRS.get("safe_unrelated_exploitation", set())


def test_benchmark_mock_run_is_offline_and_reports_correlation_metrics(monkeypatch):
    from ai import benchmark as module

    # Fail loudly if a future code edit accidentally invokes real mode in CI.
    monkeypatch.setenv("AI_MODE", "live")
    monkeypatch.delenv("SAFEHEAL_BENCHMARK_LIVE", raising=False)
    report = module.benchmark("mock")
    assert report["mode"] == "mock"
    assert report["attempted"] == len(CASES)
    assert report["errors"] == 0, report["cases"]
    assert report["completed"] == len(CASES)
    assert report["completion_rate"] == 1.0
    assert report["usage"]["total_tokens"] == 0
    assert set(report["correlation_metrics"]) == {"precision", "recall", "f1"}
    assert report["benign_cases_completed"] >= 2
    assert all(case["ai_source"] == "mock" for case in report["cases"])
    # The benchmark invokes the same combined static review as backend responses.
    assert report["cases"][0]["static_patch_passed"] is None  # safe; no patch needed
    assert report["cases"][1]["static_patch_passed"] is True  # root remediation


def test_real_mode_requires_explicit_consent_and_case_limit(monkeypatch):
    import pytest
    from ai import benchmark as module

    monkeypatch.delenv("SAFEHEAL_BENCHMARK_LIVE", raising=False)
    with pytest.raises(ValueError, match="Refusing real API calls"):
        module.benchmark("live", max_cases=1)

    monkeypatch.setenv("SAFEHEAL_BENCHMARK_LIVE", "YES")
    with pytest.raises(ValueError, match="explicit --max-cases"):
        module.benchmark("live")
    with pytest.raises(ValueError, match="max_cases"):
        module.benchmark("live", max_cases=len(CASES) + 1)


def test_unknown_categories_are_counted_as_false_positives_in_aggregation(monkeypatch):
    from ai import benchmark as module

    def stub_analyze(docker, logs, *, settings):
        assert settings.mode == "mock"
        return {
            "status": "completed",
            "findings": [{"title": "unrelated new issue"}],
            "correlations": [],
            "tests": {"proposed_patch": {"passed": False}},
            "ai": {"source": "mock"},
        }

    monkeypatch.setattr(module, "analyze_evidence", stub_analyze)
    report = module.benchmark("mock", max_cases=2)
    assert report["tp"] == 0
    assert report["fp"] == 2
    assert report["fn"] == 1
    assert report["unmapped_findings"] == 2
    assert report["benign_case_false_positive_rate"] == 1.0


def test_benchmark_report_has_no_raw_evidence_or_secrets():
    from ai import benchmark as module
    report = module.benchmark("mock", max_cases=5)
    from json import dumps
    output = dumps(report)
    assert "SYNTHETIC_BENCHMARK_SECRET" not in output
    assert "RUN useradd" not in output
    assert "FROM python:" not in output


def test_targeted_selection_runs_only_requested_cases_without_network(monkeypatch):
    from ai import benchmark as module
    seen = []

    def stub_analyze(docker, logs, *, settings):
        assert settings.mode == "mock"
        seen.append(docker)
        return {"status": "completed", "findings": [], "correlations": [],
                "ai": {"source": "mock"}, "patch": {}, "tests": {}}

    monkeypatch.setattr(module, "analyze_evidence", stub_analyze)
    report = module.benchmark("mock", case_names=["mixed_attack", "unsupported_python_base"])
    assert report["attempted"] == 2
    assert report["completed"] == 2
    assert [c["name"] for c in report["cases"]] == [
        "unsupported_python_base", "mixed_attack",
    ]
    assert len(seen) == 2


def test_targeted_diagnostics_are_coded_without_raw_model_text(monkeypatch):
    from ai import benchmark as module

    def stub_analyze(docker, logs, *, settings):
        return {"status": "completed",
                "findings": [{"title": "Deprecated runtime image PRIVATE_DO_NOT_LOG"}],
                "correlations": [], "patch": {}, "tests": {},
                "ai": {"source": "mock"}}

    monkeypatch.setattr(module, "analyze_evidence", stub_analyze)
    report = module.benchmark("mock", case_names=["unsupported_python_base"])
    case = report["cases"][0]
    assert case["unmapped_findings"] == 1
    assert set(case["unmapped_title_indicators"][0]) == {"deprecated", "runtime"}
    assert "PRIVATE_DO_NOT_LOG" not in __import__("json").dumps(report)


def test_targeted_selection_guards_invalid_and_duplicate_names():
    import pytest
    from ai import benchmark as module
    with pytest.raises(ValueError, match="Unknown case"):
        module.benchmark("mock", case_names=["not_a_case"])
    with pytest.raises(ValueError, match="unique"):
        module.benchmark("mock", case_names=["mixed_attack", "mixed_attack"])
    with pytest.raises(ValueError, match="either"):
        module.benchmark("mock", max_cases=2, case_names=["mixed_attack"])
