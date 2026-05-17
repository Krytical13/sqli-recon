import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_cli_help():
    result = subprocess.run(
        [sys.executable, "-m", "bench", "--help"],
        capture_output=True, text=True, cwd=REPO_ROOT, timeout=10,
    )
    assert result.returncode == 0
    assert "--apps" in result.stdout
    assert "--save-baseline" in result.stdout


def test_cli_apps_filter_unknown():
    """Unknown app filter doesn't crash, just runs nothing."""
    result = subprocess.run(
        [sys.executable, "-m", "bench", "--apps", "nonexistent_app", "--layer", "a"],
        capture_output=True, text=True, cwd=REPO_ROOT, timeout=30,
    )
    assert result.returncode == 0  # No regressions because no apps ran
