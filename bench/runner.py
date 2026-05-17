"""Orchestration pipeline. See spec section 7."""
import logging
from pathlib import Path
from typing import Dict, List

from bench.corpus import AppConfig, discover_apps
from bench.detector_runner import run_layer_a
from bench.e2e_runner import run_layer_b
from bench.label import load_labels
from bench.lifecycle import app_for_config
from bench.score import compare, score
from sqli_recon.http_client import HttpClient

log = logging.getLogger(__name__)


def run_for_app(
    config: AppConfig,
    layer: str = "both",
    detector_filter: List[str] = None,
    cwd: Path = None,
) -> Dict[str, Dict[str, Dict[str, Dict[str, float]]]]:
    """
    Run the harness for one app. Returns:
      {app_name: {detector_name: {layer_name: {metric: value}}}}
    """
    labels_path = config.config_path.parent / "labels.json"
    labels = load_labels(labels_path)
    log.info(f"Loaded {len(labels)} labels for {config.name}")

    app_scores: Dict[str, Dict[str, Dict[str, float]]] = {}

    with app_for_config(config, cwd=cwd) as handle:
        client = HttpClient(timeout=10, rate_limit=0.0)

        # App-specific session bootstrap if applicable
        if config.name == "dvwa":
            from bench.corpus.dvwa.bootstrap import bootstrap_session
            if not bootstrap_session(client, handle.base_url):
                log.error("DVWA session bootstrap failed — results will be unreliable")

        if layer in ("a", "both"):
            log.info(f"Running Layer A on {config.name}")
            found_a = run_layer_a(labels, handle.base_url, client, detector_filter)
            comp_a = compare(found_a, labels)
            scores_a = score(comp_a)
            for detector_name, metrics in scores_a.items():
                app_scores.setdefault(detector_name, {})["isolated"] = metrics

        if layer in ("b", "both"):
            log.info(f"Running Layer B on {config.name}")
            found_b = run_layer_b(handle.base_url, detector_filter)
            comp_b = compare(found_b, labels)
            scores_b = score(comp_b)
            for detector_name, metrics in scores_b.items():
                app_scores.setdefault(detector_name, {})["end_to_end"] = metrics

    return {config.name: app_scores}


def run_all(
    corpus_root: Path,
    app_filter: List[str] = None,
    detector_filter: List[str] = None,
    layer: str = "both",
    cwd: Path = None,
) -> Dict:
    """Run harness for all (or a filtered subset of) corpus apps."""
    apps = discover_apps(corpus_root)
    if app_filter:
        apps = [a for a in apps if a.name in app_filter]

    all_scores: Dict = {}
    for app in apps:
        try:
            app_scores = run_for_app(app, layer=layer,
                                     detector_filter=detector_filter, cwd=cwd)
            all_scores.update(app_scores)
        except Exception as e:
            log.error(f"App {app.name} failed: {e}")
            all_scores[app.name] = {"error": str(e)}

    return all_scores
