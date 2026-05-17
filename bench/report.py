"""Render harness output: terse summary + detailed tables."""
from typing import Dict, List


def render_summary(scores: Dict, regressions: List[Dict]) -> str:
    """One-line-per-app pass/fail summary."""
    lines = []
    if regressions:
        lines.append(f"\n[!] FAIL — {len(regressions)} regression(s) detected:\n")
        for r in regressions:
            lines.append(
                f"  {r['app']:>20s}  {r['detector']:>25s}  "
                f"{r['layer']:>10s}.{r['metric']:<10s}  "
                f"baseline={r['baseline']:.3f}  current={r['current']:.3f}  "
                f"delta={r['delta']:+.3f}"
            )
    else:
        lines.append("\n[+] PASS — no regressions detected\n")

    lines.append("\nSummary:")
    for app, app_scores in scores.items():
        if isinstance(app_scores, dict) and app_scores.get("error"):
            lines.append(f"  {app}: ERROR — {app_scores['error']}")
            continue
        detectors = ", ".join(sorted(app_scores.keys()))
        lines.append(f"  {app}: {len(app_scores)} detectors evaluated ({detectors})")

    return "\n".join(lines)


def render_detail_table(scores: Dict) -> str:
    """Full per-detector, per-layer breakdown table."""
    lines = [
        "",
        "=" * 100,
        f"{'App':<20s} {'Detector':<30s} {'Layer':<12s} {'Precision':>10s} {'Recall':>8s} {'F1':>8s}",
        "-" * 100,
    ]
    for app, app_scores in scores.items():
        if isinstance(app_scores, dict) and app_scores.get("error"):
            lines.append(f"{app:<20s} ERROR: {app_scores['error']}")
            continue
        for detector_name, layer_scores in sorted(app_scores.items()):
            for layer_name, metrics in sorted(layer_scores.items()):
                lines.append(
                    f"{app:<20s} {detector_name:<30s} {layer_name:<12s} "
                    f"{metrics['precision']:>10.3f} {metrics['recall']:>8.3f} {metrics['f1']:>8.3f}"
                )
    lines.append("=" * 100)
    return "\n".join(lines)
