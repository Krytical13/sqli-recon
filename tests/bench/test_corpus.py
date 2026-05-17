from pathlib import Path

import pytest

from bench.corpus import discover_apps, load_app_config, AppConfig


FIXTURE = Path(__file__).parent / "fixtures" / "sample_app.yaml"
REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_ROOT = REPO_ROOT / "bench" / "corpus"


def test_load_app_config_basic():
    cfg = load_app_config(FIXTURE)
    assert isinstance(cfg, AppConfig)
    assert cfg.name == "testapp"
    assert cfg.kind == "docker"
    assert cfg.image == "example/test:latest"
    assert cfg.port == 8080
    assert cfg.healthcheck_url == "http://127.0.0.1:8080/health"


def test_load_app_config_process_kind():
    cfg = load_app_config(CORPUS_ROOT / "vulnerable_app" / "app.yaml")
    assert cfg.kind == "process"
    # command should be a list starting with python3 (or python)
    assert isinstance(cfg.command, list)
    assert "tests/vulnerable_app.py" in cfg.command


def test_discover_apps_returns_vulnerable_app():
    apps = discover_apps(CORPUS_ROOT)
    names = [a.name for a in apps]
    assert "vulnerable_app" in names


def test_load_app_config_rejects_unknown_kind():
    bad = FIXTURE.parent / "bad_app.yaml"
    bad.write_text("name: x\nkind: telepathy\nport: 1\nhealthcheck:\n  url: http://x\n  timeout: 1\n")
    try:
        with pytest.raises(ValueError, match="telepathy"):
            load_app_config(bad)
    finally:
        bad.unlink()
