"""App lifecycle managers — start, healthcheck, teardown.

ProcessApp: kind=process (subprocess)
DockerApp:  kind=docker (docker run --rm)
"""
import logging
import shutil
import socket
import subprocess
import time
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import requests

from bench.corpus import AppConfig

log = logging.getLogger(__name__)


@dataclass
class AppHandle:
    """What gets yielded by a started app context."""
    base_url: str
    config: AppConfig


def _wait_for_health(url: str, timeout: int) -> bool:
    """Poll URL until it answers or timeout. Returns True on success."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = requests.get(url, timeout=2)
            if resp.status_code < 500:
                return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(0.5)
    return False


def _port_in_use(port: int) -> bool:
    """Cheap check whether something is listening on 127.0.0.1:port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        return s.connect_ex(("127.0.0.1", port)) == 0
    finally:
        s.close()


def _run_setup_steps(steps, base_url):
    """Execute setup commands declared in app.yaml. Each step: {http: METHOD, path: /x, data: {...}}"""
    for step in steps:
        if "http" in step:
            method = step["http"].upper()
            url = base_url + step["path"]
            data = step.get("data")
            log.info(f"setup: {method} {url}")
            requests.request(method, url, data=data, timeout=10)


class ProcessApp(AbstractContextManager):
    """Run a corpus app as a subprocess."""

    def __init__(self, config: AppConfig, cwd: Optional[Path] = None):
        self.config = config
        self.cwd = cwd
        self._proc: Optional[subprocess.Popen] = None

    def __enter__(self) -> AppHandle:
        if _port_in_use(self.config.port):
            raise RuntimeError(
                f"Port {self.config.port} already in use — "
                f"another instance of {self.config.name}?"
            )

        log.info(f"Starting {self.config.name}: {' '.join(self.config.command)}")
        self._proc = subprocess.Popen(
            self.config.command, cwd=self.cwd,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        if not _wait_for_health(self.config.healthcheck_url, self.config.healthcheck_timeout):
            self._proc.terminate()
            raise RuntimeError(f"{self.config.name} did not pass healthcheck")

        base_url = f"http://127.0.0.1:{self.config.port}"
        _run_setup_steps(self.config.setup, base_url)
        return AppHandle(base_url=base_url, config=self.config)

    def __exit__(self, exc_type, exc, tb):
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
        return False


class DockerApp(AbstractContextManager):
    """Run a corpus app as a docker container."""

    def __init__(self, config: AppConfig):
        self.config = config
        self._container_id: Optional[str] = None

    def __enter__(self) -> AppHandle:
        if not shutil.which("docker"):
            raise RuntimeError(f"docker not installed — cannot start {self.config.name}")
        if _port_in_use(self.config.port):
            raise RuntimeError(f"Port {self.config.port} already in use")

        log.info(f"Starting {self.config.name} from image {self.config.image}")
        result = subprocess.run(
            ["docker", "run", "-d", "--rm",
             "-p", f"{self.config.port}:80",
             self.config.image],
            capture_output=True, text=True, check=True,
        )
        self._container_id = result.stdout.strip()

        if not _wait_for_health(self.config.healthcheck_url, self.config.healthcheck_timeout):
            self._teardown()
            raise RuntimeError(f"{self.config.name} did not pass healthcheck")

        base_url = f"http://127.0.0.1:{self.config.port}"
        _run_setup_steps(self.config.setup, base_url)
        return AppHandle(base_url=base_url, config=self.config)

    def __exit__(self, exc_type, exc, tb):
        self._teardown()
        return False

    def _teardown(self):
        if self._container_id:
            subprocess.run(["docker", "stop", self._container_id],
                           capture_output=True, timeout=15)
            self._container_id = None


def app_for_config(config: AppConfig, cwd: Optional[Path] = None):
    """Factory: returns the right lifecycle manager for the config's kind."""
    if config.kind == "process":
        return ProcessApp(config, cwd=cwd)
    elif config.kind == "docker":
        return DockerApp(config)
    raise ValueError(f"Unknown kind: {config.kind}")
