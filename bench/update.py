"""Refresh corpus labels from upstream sources."""
import json
import logging
import subprocess
from dataclasses import asdict
from pathlib import Path

log = logging.getLogger(__name__)


def update_all_labels(corpus_root: Path):
    """
    For each corpus app, re-run its extractor and write fresh labels.json.
    For docker-based apps, pull the latest image first.
    """
    from bench.corpus import discover_apps

    for app in discover_apps(corpus_root):
        log.info(f"Updating labels for {app.name}")

        if app.kind == "docker" and app.image:
            log.info(f"Pulling latest {app.image}")
            subprocess.run(["docker", "pull", app.image], check=False)

        module_path = f"bench.corpus.{app.name}.extractor"
        extractor_mod = __import__(module_path, fromlist=["extract"])
        labels = extractor_mod.extract()

        data = []
        for lab in labels:
            d = asdict(lab)
            d["location"] = d["location"].value
            d["vuln_types"] = [v.value for v in d["vuln_types"]]
            data.append(d)

        out_path = app.config_path.parent / "labels.json"
        out_path.write_text(json.dumps(data, indent=2))
        log.info(f"  wrote {len(data)} labels to {out_path}")
