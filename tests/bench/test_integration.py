import pytest
from pathlib import Path

from bench.runner import run_for_app
from bench.corpus import load_app_config

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.integration
@pytest.mark.dvwa
def test_run_for_dvwa():
    """Full harness against DVWA in docker. Requires docker + DVWA image pre-pulled."""
    import shutil
    if not shutil.which("docker"):
        pytest.skip("docker not installed")
    cfg = load_app_config(REPO_ROOT / "bench" / "corpus" / "dvwa" / "app.yaml")
    scores = run_for_app(cfg, layer="a", cwd=REPO_ROOT)  # Layer A only for speed

    assert "dvwa" in scores
    assert "ErrorDetector" in scores["dvwa"]
    isolated_recall = scores["dvwa"]["ErrorDetector"]["isolated"]["recall"]
    assert isolated_recall > 0


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
