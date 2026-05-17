from bench.label import Label
from bench.score import compare, score, diff_vs_baseline
from sqli_recon.models import ParamLocation, VulnType


def _label(app, path, param, vuln_types, method="GET"):
    return Label(app=app, url_path=path, method=method, parameter=param,
                 location=ParamLocation.QUERY, vuln_types=vuln_types, context={})


def test_compare_true_positive():
    labels = [_label("app", "/users", "id", [VulnType.SQLI])]
    found = {"ErrorDetector": {("/users", "GET", "id")}}
    result = compare(found, labels)
    assert result["ErrorDetector"] == {"tp": 1, "fp": 0, "fn": 0}


def test_compare_false_positive():
    labels = [_label("app", "/about", "id", [])]
    found = {"ErrorDetector": {("/about", "GET", "id")}}
    result = compare(found, labels)
    assert result["ErrorDetector"] == {"tp": 0, "fp": 1, "fn": 0}


def test_compare_false_negative():
    labels = [_label("app", "/users", "id", [VulnType.SQLI])]
    found = {"ErrorDetector": set()}
    result = compare(found, labels)
    assert result["ErrorDetector"] == {"tp": 0, "fp": 0, "fn": 1}


def test_compare_multiple_detectors():
    labels = [
        _label("app", "/users", "id", [VulnType.SQLI]),
        _label("app", "/render", "tpl", [VulnType.SSTI]),
    ]
    found = {
        "ErrorDetector": {("/users", "GET", "id")},
        "SSTIDetector": {("/render", "GET", "tpl")},
    }
    result = compare(found, labels)
    assert result["ErrorDetector"] == {"tp": 1, "fp": 0, "fn": 0}
    assert result["SSTIDetector"] == {"tp": 1, "fp": 0, "fn": 0}


def test_compare_finding_outside_labels_logged_not_counted():
    """Findings on unlabeled endpoints don't count (no ground truth)."""
    labels = [_label("app", "/users", "id", [VulnType.SQLI])]
    found = {"ErrorDetector": {("/users", "GET", "id"),
                                ("/unknown", "GET", "x")}}
    result = compare(found, labels)
    assert result["ErrorDetector"] == {"tp": 1, "fp": 0, "fn": 0}


def test_score_precision_recall_f1():
    comparison = {"ErrorDetector": {"tp": 8, "fp": 2, "fn": 1}}
    result = score(comparison)
    assert abs(result["ErrorDetector"]["precision"] - 0.8) < 0.01
    assert abs(result["ErrorDetector"]["recall"] - 0.889) < 0.01
    assert abs(result["ErrorDetector"]["f1"] - 0.842) < 0.01


def test_score_zero_division_safe():
    comparison = {"ErrorDetector": {"tp": 0, "fp": 0, "fn": 0}}
    result = score(comparison)
    assert result["ErrorDetector"] == {"precision": 0.0, "recall": 0.0, "f1": 0.0}


def test_diff_vs_baseline_no_regression():
    baseline = {"app": {"ErrorDetector": {"isolated": {"precision": 0.9, "recall": 0.8, "f1": 0.85}}}}
    current = {"app": {"ErrorDetector": {"isolated": {"precision": 0.92, "recall": 0.81, "f1": 0.86}}}}
    regressions = diff_vs_baseline(current, baseline, threshold=0.05)
    assert regressions == []


def test_compare_unknown_detector_returns_zeros():
    """A detector name not in DETECTOR_VULN_TYPE produces all zeros, no exception."""
    labels = [_label("app", "/users", "id", [VulnType.SQLI])]
    found = {"BogusDetector": {("/users", "GET", "id")}}
    result = compare(found, labels)
    assert result["BogusDetector"] == {"tp": 0, "fp": 0, "fn": 0}


def test_diff_vs_baseline_detects_regression():
    baseline = {"app": {"ErrorDetector": {"isolated": {"precision": 0.9, "recall": 0.8, "f1": 0.85}}}}
    current = {"app": {"ErrorDetector": {"isolated": {"precision": 0.6, "recall": 0.8, "f1": 0.69}}}}
    regressions = diff_vs_baseline(current, baseline, threshold=0.05)
    assert len(regressions) >= 1
    assert any("precision" in r["metric"] for r in regressions)
    assert any(r["app"] == "app" for r in regressions)


def test_diff_vs_baseline_missing_keys_safe():
    """New detector not in baseline = no regression (just informational)."""
    baseline = {"app": {"ErrorDetector": {"isolated": {"precision": 0.9, "recall": 0.8, "f1": 0.85}}}}
    current = {"app": {
        "ErrorDetector": {"isolated": {"precision": 0.9, "recall": 0.8, "f1": 0.85}},
        "NewDetector":   {"isolated": {"precision": 0.5, "recall": 0.5, "f1": 0.5}},
    }}
    regressions = diff_vs_baseline(current, baseline, threshold=0.05)
    assert regressions == []
