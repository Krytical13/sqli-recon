import time
from pathlib import Path

import pytest
import requests

from bench.corpus import load_app_config
from bench.lifecycle import ProcessApp, app_for_config

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_process_app_lifecycle():
    """vulnerable_app must start, respond to healthcheck, and stop cleanly."""
    cfg = load_app_config(REPO_ROOT / "bench" / "corpus" / "vulnerable_app" / "app.yaml")
    with ProcessApp(cfg, cwd=REPO_ROOT) as handle:
        assert handle.base_url.endswith(":18484")
        resp = requests.get(handle.base_url, timeout=5)
        assert resp.status_code in (200, 404)

    # After __exit__, process should be gone
    time.sleep(0.2)
    with pytest.raises(requests.exceptions.ConnectionError):
        requests.get("http://127.0.0.1:18484/", timeout=2)


def test_app_for_config_dispatches_on_kind():
    cfg = load_app_config(REPO_ROOT / "bench" / "corpus" / "vulnerable_app" / "app.yaml")
    app = app_for_config(cfg, cwd=REPO_ROOT)
    assert isinstance(app, ProcessApp)
