"""CLI entry point for the detector accuracy harness."""
import argparse


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
                   help="Comma-separated subset of detectors")
    p.add_argument("--save-baseline", action="store_true",
                   help="Persist current scores as new baseline")
    p.add_argument("--update-labels", action="store_true",
                   help="Refresh corpus labels from upstream")
    p.add_argument("--layer", choices=["a", "b", "both"], default="both",
                   help="Run only Layer A (isolated), Layer B (end-to-end), or both")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    print(f"bench v0.1.0 — placeholder (args: {vars(args)})")
    return 0
