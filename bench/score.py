"""Pure scoring functions. See spec section 6.3.

compare(): findings vs labels -> per-detector TP/FP/FN counts
score():   counts -> precision/recall/f1
diff_vs_baseline(): current scores vs prior baseline -> regressions
"""
from typing import Dict, List, Set, Tuple

from bench.label import Label
from sqli_recon.models import VulnType


# Which VulnType each detector confirms — used to attribute Layer B findings
DETECTOR_VULN_TYPE = {
    "ErrorDetector": VulnType.SQLI,
    "SSTIDetector": VulnType.SSTI,
    "CommandInjectionDetector": VulnType.CMDI,
    "HeaderInjectionScanner": VulnType.SQLI,  # also detects SQLi (via headers)
}


def compare(
    found: Dict[str, Set[Tuple[str, str, str]]],
    labels: List[Label],
) -> Dict[str, Dict[str, int]]:
    """
    Compare per-detector findings to labeled ground truth.

    Args:
        found: detector_name -> set of (url_path, method, parameter) confirmed
        labels: list of Label objects (ground truth)

    Returns:
        detector_name -> {"tp": N, "fp": N, "fn": N}

    Findings on endpoints not in labels are dropped (no ground truth).
    Findings on endpoints in labels but where vuln_types doesn't include
    the detector's vuln_type count as false positives.
    """
    label_index = {}
    for lab in labels:
        key = (lab.url_path, lab.method, lab.parameter)
        label_index[key] = set(lab.vuln_types)

    result = {}
    for detector_name, found_set in found.items():
        expected_vuln_type = DETECTOR_VULN_TYPE.get(detector_name)
        tp = fp = fn = 0

        for finding_key in found_set:
            if finding_key not in label_index:
                continue
            label_vuln_types = label_index[finding_key]
            if expected_vuln_type in label_vuln_types:
                tp += 1
            else:
                fp += 1

        for label_key, vuln_types in label_index.items():
            if expected_vuln_type in vuln_types and label_key not in found_set:
                fn += 1

        result[detector_name] = {"tp": tp, "fp": fp, "fn": fn}

    return result


def score(comparison: Dict[str, Dict[str, int]]) -> Dict[str, Dict[str, float]]:
    """Convert TP/FP/FN counts to precision/recall/F1."""
    result = {}
    for detector_name, counts in comparison.items():
        tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)
              if (precision + recall) > 0 else 0.0)
        result[detector_name] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }
    return result


def diff_vs_baseline(
    current: Dict[str, Dict[str, Dict[str, Dict[str, float]]]],
    baseline: Dict[str, Dict[str, Dict[str, Dict[str, float]]]],
    threshold: float = 0.05,
) -> List[Dict]:
    """
    Compare current scores to baseline, return regressions.

    Structure: {app -> {detector -> {layer -> {metric -> value}}}}
    A regression is any metric drop > threshold.
    New detectors/apps in current but not baseline are informational only.
    """
    regressions = []
    for app, app_scores in current.items():
        baseline_app = baseline.get(app, {})
        for detector, detector_scores in app_scores.items():
            baseline_detector = baseline_app.get(detector, {})
            for layer, layer_scores in detector_scores.items():
                baseline_layer = baseline_detector.get(layer, {})
                for metric, value in layer_scores.items():
                    baseline_value = baseline_layer.get(metric)
                    if baseline_value is None:
                        continue
                    delta = value - baseline_value
                    if delta < -threshold:
                        regressions.append({
                            "app": app,
                            "detector": detector,
                            "layer": layer,
                            "metric": metric,
                            "baseline": baseline_value,
                            "current": value,
                            "delta": delta,
                        })
    return regressions
