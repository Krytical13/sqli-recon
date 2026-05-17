"""Corpus app discovery + app.yaml loading."""
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml

VALID_KINDS = {"process", "docker"}


@dataclass
class AppConfig:
    name: str
    kind: str  # "process" or "docker"
    port: int
    healthcheck_url: str
    healthcheck_timeout: int = 30
    command: Optional[List[str]] = None  # for kind=process
    image: Optional[str] = None          # for kind=docker
    setup: List[dict] = field(default_factory=list)
    teardown: List[dict] = field(default_factory=list)
    config_path: Optional[Path] = None


def load_app_config(path: Path) -> AppConfig:
    """Parse an app.yaml into an AppConfig."""
    data = yaml.safe_load(Path(path).read_text())
    kind = data.get("kind")
    if kind not in VALID_KINDS:
        raise ValueError(f"Unknown app kind '{kind}' in {path} — must be one of {VALID_KINDS}")

    hc = data.get("healthcheck", {})
    return AppConfig(
        name=data["name"],
        kind=kind,
        port=data["port"],
        healthcheck_url=hc.get("url", f"http://127.0.0.1:{data['port']}/"),
        healthcheck_timeout=hc.get("timeout", 30),
        command=data.get("command"),
        image=data.get("image"),
        setup=data.get("setup") or [],
        teardown=data.get("teardown") or [],
        config_path=Path(path),
    )


def discover_apps(corpus_root: Path) -> List[AppConfig]:
    """Scan corpus_root for any subdir containing app.yaml."""
    apps = []
    for subdir in sorted(Path(corpus_root).iterdir()):
        if not subdir.is_dir():
            continue
        app_yaml = subdir / "app.yaml"
        if app_yaml.exists():
            apps.append(load_app_config(app_yaml))
    return apps
