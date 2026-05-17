import pytest
from pathlib import Path

from bench.runner import run_for_app
from bench.corpus import load_app_config

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.integration
def test_run_for_vulnerable_app():
    """Full harness against the real vulnerable_app. Slow."""
    cfg = load_app_config(REPO_ROOT / "bench" / "corpus" / "vulnerable_app" / "app.yaml")
    scores = run_for_app(cfg, layer="both", cwd=REPO_ROOT)

    assert "vulnerable_app" in scores
    detector_scores = scores["vulnerable_app"]
    assert "ErrorDetector" in detector_scores
    assert "isolated" in detector_scores["ErrorDetector"]
    assert "end_to_end" in detector_scores["ErrorDetector"]
    # Should find at least one SQLi via Layer A
    isolated_recall = detector_scores["ErrorDetector"]["isolated"]["recall"]
    assert isolated_recall > 0, "ErrorDetector should find at least one known SQLi via Layer A"
