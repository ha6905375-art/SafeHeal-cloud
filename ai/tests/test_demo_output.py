"""
Regression: `python -m ai.demo` crashed with UnicodeEncodeError when its output was
redirected to a file on Windows (cp1252) and the model's text contained U+2011.
The live analysis had completed, but the result was lost. Offline: no API call.
"""

import io
import sys

from ai import demo

NON_ASCII = "non‑root"  # the character from the real live reply


def fake_result():
    return {
        "status": "completed",
        "findings": [{"id": "F-001", "title": f"Runs as {NON_ASCII} user", "severity": "HIGH",
                      "description": "d", "recommendation": "r"}],
        "correlations": [], "patch": {"patched_dockerfile": "", "diff": "", "summary": ""},
        "tests": {"status": "not_run", "passed": None, "details": []},
        "response": {"mode": "simulation", "actions": []},
        "ai": {"source": "mock", "model": "mock-rule-based", "error": None},
    }


def test_demo_output_redirected_to_cp1252_does_not_crash(monkeypatch):
    raw = io.BytesIO()
    stdout = io.TextIOWrapper(raw, encoding="cp1252")  # what Windows uses for a redirected file
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "argv", ["ai.demo", "--mode", "mock"])
    monkeypatch.setattr(demo, "analyze_evidence", lambda *args, **kwargs: fake_result())

    assert demo.main() == 0
    stdout.flush()
    text = raw.getvalue().decode("utf-8")
    assert NON_ASCII in text
    assert '"status": "completed"' in text
