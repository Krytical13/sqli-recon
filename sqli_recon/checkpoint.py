"""Checkpoint/resume — save scan state to disk, resume from where we left off."""

import json
import os
import logging
from dataclasses import asdict

from sqli_recon.models import Endpoint, Parameter, ParamLocation, Source

log = logging.getLogger(__name__)

CHECKPOINT_FILE = "scan_checkpoint.json"


def save_checkpoint(output_dir, phase, endpoints, js_urls=None, findings=None, metadata=None):
    """Save current scan state to a checkpoint file."""
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, CHECKPOINT_FILE)

    state = {
        "phase": phase,
        "metadata": metadata or {},
        "endpoints": [_serialize_endpoint(ep) for ep in endpoints],
        "js_urls": list(js_urls or []),
    }
    if findings:
        state["findings"] = [
            {
                "endpoint_url": f.endpoint.url,
                "endpoint_method": f.endpoint.method,
                "param_name": f.parameter.name,
                "param_location": f.parameter.location.value,
                "score": f.score,
                "reasons": f.reasons,
            }
            for f in findings
        ]

    with open(path, "w") as f:
        json.dump(state, f, indent=2)
    log.debug(f"Checkpoint saved: phase={phase}, endpoints={len(endpoints)}")


def load_checkpoint(output_dir):
    """Load a checkpoint file if it exists. Returns (phase, endpoints, js_urls, metadata) or None."""
    path = os.path.join(output_dir, CHECKPOINT_FILE)
    if not os.path.exists(path):
        return None

    try:
        with open(path) as f:
            state = json.load(f)

        phase = state["phase"]
        endpoints = [_deserialize_endpoint(ep) for ep in state.get("endpoints", [])]
        js_urls = state.get("js_urls", [])
        metadata = state.get("metadata", {})

        log.info(f"Checkpoint loaded: phase={phase}, endpoints={len(endpoints)}")
        return phase, endpoints, js_urls, metadata
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        log.warning(f"Corrupt checkpoint file: {e}")
        return None


def clear_checkpoint(output_dir):
    """Remove checkpoint file after successful completion."""
    path = os.path.join(output_dir, CHECKPOINT_FILE)
    if os.path.exists(path):
        os.remove(path)


def _serialize_endpoint(ep):
    return {
        "url": ep.url,
        "method": ep.method,
        "parameters": [
            {
                "name": p.name,
                "location": p.location.value,
                "value": p.value,
                "param_type": p.param_type,
            }
            for p in ep.parameters
        ],
        "content_type": ep.content_type,
        "source": ep.source.value,
        "status_code": ep.status_code,
        "body_template": ep.body_template,
    }


def _deserialize_endpoint(data):
    params = [
        Parameter(
            name=p["name"],
            location=ParamLocation(p["location"]),
            value=p.get("value", ""),
            param_type=p.get("param_type", "string"),
        )
        for p in data.get("parameters", [])
    ]
    return Endpoint(
        url=data["url"],
        method=data.get("method", "GET"),
        parameters=params,
        content_type=data.get("content_type", ""),
        source=Source(data.get("source", "crawl")),
        status_code=data.get("status_code", 0),
        body_template=data.get("body_template", ""),
    )
