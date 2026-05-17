"""Normalized label model + loader. See spec section 6.2."""
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from sqli_recon.models import ParamLocation, VulnType


@dataclass
class Label:
    app: str
    url_path: str
    method: str
    parameter: str
    location: ParamLocation
    vuln_types: List[VulnType] = field(default_factory=list)
    context: dict = field(default_factory=dict)


def load_labels(path: Path) -> List[Label]:
    """Load labels from a corpus's labels.json file."""
    data = json.loads(Path(path).read_text())
    labels = []
    for idx, entry in enumerate(data):
        try:
            try:
                location = ParamLocation(entry["location"])
            except ValueError as e:
                raise ValueError(f"Unknown location '{entry['location']}' in {path}") from e
            try:
                vuln_types = [VulnType(v) for v in entry.get("vuln_types", [])]
            except ValueError as e:
                raise ValueError(f"Unknown vuln_type in {path}: {e}") from e

            labels.append(Label(
                app=entry["app"],
                url_path=entry["url_path"],
                method=entry["method"],
                parameter=entry.get("parameter", ""),
                location=location,
                vuln_types=vuln_types,
                context=entry.get("context", {}),
            ))
        except KeyError as e:
            raise ValueError(
                f"Malformed label entry at index {idx} in {path}: missing required field {e}"
            ) from e
    return labels
