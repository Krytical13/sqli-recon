from bench.report import render_summary, render_detail_table


SAMPLE_SCORES = {
    "vulnerable_app": {
        "ErrorDetector": {
            "isolated":  {"precision": 1.0, "recall": 0.85, "f1": 0.92},
            "end_to_end": {"precision": 0.9, "recall": 0.80, "f1": 0.85},
        },
        "SSTIDetector": {
            "isolated":  {"precision": 0.9, "recall": 0.75, "f1": 0.82},
            "end_to_end": {"precision": 0.8, "recall": 0.70, "f1": 0.75},
        },
    },
}


def test_render_summary_no_regressions():
    out = render_summary(SAMPLE_SCORES, regressions=[])
    assert "PASS" in out
    assert "vulnerable_app" in out


def test_render_summary_with_regressions():
    regs = [{"app": "vulnerable_app", "detector": "ErrorDetector",
             "layer": "isolated", "metric": "recall",
             "baseline": 0.95, "current": 0.85, "delta": -0.10}]
    out = render_summary(SAMPLE_SCORES, regressions=regs)
    assert "FAIL" in out or "REGRESSION" in out
    assert "ErrorDetector" in out
    assert "0.10" in out or "10%" in out or "-0.1" in out


def test_render_detail_table_includes_metrics():
    out = render_detail_table(SAMPLE_SCORES)
    assert "ErrorDetector" in out
    assert "SSTIDetector" in out
    assert "isolated" in out
    assert "end_to_end" in out
    assert "0.85" in out or "0.8500" in out
