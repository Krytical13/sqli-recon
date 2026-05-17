"""Extracts labels from `# VULN:` annotations in tests/vulnerable_app.py."""
import re
from pathlib import Path
from typing import List

from bench.label import Label
from sqli_recon.models import ParamLocation, VulnType

REPO_ROOT = Path(__file__).resolve().parents[3]
VULNERABLE_APP_PATH = REPO_ROOT / "tests" / "vulnerable_app.py"

# Matches: # VULN: clean
CLEAN_RE = re.compile(r"#\s*VULN:\s*clean\s*$", re.I)

# Matches: # VULN: vuln_type=sqli, param=q, location=query
VULN_RE = re.compile(
    r"#\s*VULN:\s*vuln_type=(\w+)\s*,\s*param=([\w\[\]]+)\s*,\s*location=(\w+)",
    re.I,
)

# Matches: @app.route("/path", methods=["POST"])  or  @app.route('/path')
ROUTE_RE = re.compile(
    r"""@app\.route\(\s*['"]([^'"]+)['"](?:\s*,\s*methods=\[([^\]]+)\])?""",
)


def extract() -> List[Label]:
    """Parse vulnerable_app.py and return labels for annotated routes."""
    if not VULNERABLE_APP_PATH.exists():
        raise FileNotFoundError(f"vulnerable_app.py not found at {VULNERABLE_APP_PATH}")

    lines = VULNERABLE_APP_PATH.read_text().splitlines()
    labels = []

    pending_annotations = []
    for line in lines:
        stripped = line.strip()

        if stripped.startswith("#"):
            if CLEAN_RE.search(stripped):
                pending_annotations.append({"clean": True})
            else:
                m = VULN_RE.search(stripped)
                if m:
                    vt, param, loc = m.group(1).lower(), m.group(2), m.group(3).lower()
                    pending_annotations.append({
                        "vuln_type": vt, "param": param, "location": loc,
                    })
            continue

        if stripped.startswith("@app.route"):
            m = ROUTE_RE.search(stripped)
            if not m or not pending_annotations:
                pending_annotations = []
                continue
            path = m.group(1)
            methods_str = m.group(2) or '"GET"'
            methods = [s.strip().strip("'\"") for s in methods_str.split(",")]
            if not methods:
                methods = ["GET"]

            if any(a.get("clean") for a in pending_annotations):
                for method in methods:
                    labels.append(Label(
                        app="vulnerable_app", url_path=path, method=method,
                        parameter="", location=ParamLocation.QUERY,
                        vuln_types=[], context={},
                    ))
            else:
                for ann in pending_annotations:
                    if ann.get("clean"):
                        continue
                    try:
                        location = ParamLocation(ann["location"])
                        vuln_type = VulnType(ann["vuln_type"])
                    except ValueError as e:
                        raise ValueError(
                            f"Invalid VULN annotation for {path}: {ann} ({e})"
                        ) from e
                    for method in methods:
                        labels.append(Label(
                            app="vulnerable_app", url_path=path, method=method,
                            parameter=ann["param"], location=location,
                            vuln_types=[vuln_type], context={},
                        ))

            pending_annotations = []
        else:
            if not stripped.startswith("@") and stripped and not stripped.startswith('"""'):
                pending_annotations = []

    return labels
