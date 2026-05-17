"""CLI entry point for the detector accuracy harness."""
import argparse
import json
import logging
import sys
from pathlib import Path

from bench import __version__

REPO_ROOT = Path(__file__).resolve().parents[1]
BENCH_ROOT = Path(__file__).resolve().parent
CORPUS_ROOT = BENCH_ROOT / "corpus"
BASELINE_PATH = BENCH_ROOT / "baseline.json"


def build_parser():
    p = argparse.ArgumentParser(
        prog="bench",
        description="Detector accuracy harness for sqli-recon. "
                    "Measures precision/recall against labeled corpus.",
    )
    p.add_argument("--detail", action="store_true",
                   help="Show full per-finding breakdown")
    p.add_argument("--apps", type=str, default=None,
                   help="Comma-separated subset of corpus apps")
    p.add_argument("--detectors", type=str, default=None,
                   help="Comma-separated detector substrings to filter")
    p.add_argument("--save-baseline", action="store_true",
                   help="Persist current scores as new baseline (overwrite baseline.json)")
    p.add_argument("--update-labels", action="store_true",
                   help="Refresh corpus labels from upstream and exit")
    p.add_argument("--layer", choices=["a", "b", "both"], default="both",
                   help="Run only Layer A (isolated), Layer B (end-to-end), or both")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    # --update-labels: refresh and exit
    if args.update_labels:
        from bench.update import update_all_labels
        update_all_labels(CORPUS_ROOT)
        print("[+] Labels updated.")
        return 0

    from bench.runner import run_all
    from bench.score import diff_vs_baseline
    from bench.report import render_summary, render_detail_table

    app_filter = args.apps.split(",") if args.apps else None
    detector_filter = args.detectors.split(",") if args.detectors else None

    scores = run_all(
        corpus_root=CORPUS_ROOT,
        app_filter=app_filter,
        detector_filter=detector_filter,
        layer=args.layer,
        cwd=REPO_ROOT,
    )

    if BASELINE_PATH.exists():
        baseline = json.loads(BASELINE_PATH.read_text())
        regressions = diff_vs_baseline(scores, baseline)
    else:
        BASELINE_PATH.write_text(json.dumps(scores, indent=2))
        print(f"[*] No baseline found — created {BASELINE_PATH}")
        baseline = scores
        regressions = []

    if args.save_baseline:
        BASELINE_PATH.write_text(json.dumps(scores, indent=2))
        print(f"[+] Baseline saved to {BASELINE_PATH}")

    print(render_summary(scores, regressions))
    if args.detail:
        print(render_detail_table(scores))

    return 1 if regressions else 0


if __name__ == "__main__":
    sys.exit(main())
