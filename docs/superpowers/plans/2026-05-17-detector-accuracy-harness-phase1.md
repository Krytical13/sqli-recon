# Detector Accuracy Harness — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `bench/` engine that measures sqli-recon's detector accuracy against `vulnerable_app` and DVWA, with two-layer measurement (isolated per-detector + end-to-end pipeline), baseline-diff regression detection, and a self-contained CLI.

**Architecture:** Pluggable per-app corpus adapters (`bench/corpus/<app>/{app.yaml, extractor.py, labels.json}`) feed a runner that orchestrates app lifecycle, invokes detectors two ways, compares findings to labels, scores precision/recall/F1, and diffs against a persisted `baseline.json`. End users never touch `bench/`; `setup.sh` (top-level) stays unchanged.

**Tech Stack:** Python 3.8+, pytest, requests, PyYAML, Docker (DVWA only), no new runtime deps for end users.

**Spec reference:** `docs/superpowers/specs/2026-05-17-detector-accuracy-harness-design.md`

---

## File Structure

**New files (created by this plan):**

```
bench/
├── __init__.py             # Package marker, __version__
├── __main__.py             # `python -m bench` entry
├── cli.py                  # argparse + dispatch
├── runner.py               # orchestration pipeline
├── label.py                # Label dataclass + load_labels()
├── score.py                # compare(), score(), diff_vs_baseline() — pure
├── corpus.py               # app discovery + app.yaml loader
├── lifecycle.py            # ProcessApp / DockerApp lifecycle managers
├── detector_runner.py      # Layer A: synthetic Finding invocation
├── e2e_runner.py           # Layer B: end-to-end scan invocation
├── report.py               # render_summary(), render_detail_table()
├── update.py               # --update-labels logic
├── config.toml             # regression_threshold = 0.05
├── setup.sh                # dev install (docker check, image pull)
├── README.md               # maintainer-only framing + usage
└── corpus/
    ├── vulnerable_app/
    │   ├── app.yaml
    │   ├── extractor.py    # parses # VULN: annotations from tests/vulnerable_app.py
    │   └── labels.json     # committed
    └── dvwa/
        ├── app.yaml
        ├── extractor.py    # maps DVWA URL patterns to labels
        └── labels.json     # committed

tests/bench/
├── __init__.py
├── test_label.py
├── test_score.py
├── test_corpus.py
├── test_lifecycle.py
├── test_detector_runner.py
├── test_e2e_runner.py
├── test_integration.py     # full harness run against vulnerable_app
└── fixtures/
    ├── sample_labels.json
    └── sample_app.yaml
```

**Modified files:**

- `tests/vulnerable_app.py` — add `# VULN:` annotations next to vulnerable view handlers
- `pyproject.toml` — add `[project.optional-dependencies] bench = ["pyyaml>=6.0"]`
- `.gitignore` — add `bench/last_run.log`, `bench/baseline.json.tmp`

---

## Task 1: Bootstrap `bench/` scaffolding

**Files:**
- Create: `bench/__init__.py`, `bench/__main__.py`, `bench/cli.py`, `bench/config.toml`, `bench/README.md`, `bench/setup.sh`, `tests/bench/__init__.py`
- Modify: `pyproject.toml`, `.gitignore`

- [ ] **Step 1: Write the import-test**

`tests/bench/test_smoke.py`:
```python
def test_bench_importable():
    import bench
    assert hasattr(bench, "__version__")

def test_bench_runnable_as_module():
    import subprocess
    result = subprocess.run(
        ["python", "-m", "bench", "--help"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    assert "bench" in result.stdout.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_smoke.py -v
```
Expected: FAIL — `bench` module not found.

- [ ] **Step 3: Create scaffolding files**

`bench/__init__.py`:
```python
"""Detector accuracy harness — see bench/README.md."""
__version__ = "0.1.0"
```

`bench/__main__.py`:
```python
from bench.cli import main

if __name__ == "__main__":
    main()
```

`bench/cli.py` (placeholder — will be expanded in Task 13):
```python
"""CLI entry point for the detector accuracy harness."""
import argparse


def build_parser():
    p = argparse.ArgumentParser(
        prog="bench",
        description="Detector accuracy harness for sqli-recon. "
                    "Measures precision/recall against labeled corpus.",
    )
    p.add_argument("--detail", action="store_true",
                   help="Show full per-finding breakdown")
    p.add_argument("--apps", type=str, default=None,
                   help="Comma-separated subset of corpus apps")
    p.add_argument("--detectors", type=str, default=None,
                   help="Comma-separated subset of detectors")
    p.add_argument("--save-baseline", action="store_true",
                   help="Persist current scores as new baseline")
    p.add_argument("--update-labels", action="store_true",
                   help="Refresh corpus labels from upstream")
    p.add_argument("--layer", choices=["a", "b", "both"], default="both",
                   help="Run only Layer A (isolated), Layer B (end-to-end), or both")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    print(f"bench v0.1.0 — placeholder (args: {vars(args)})")
    return 0
```

`bench/config.toml`:
```toml
# Regression detection threshold. Any per-metric drop greater than this fails.
regression_threshold = 0.05

# Per-app overrides (optional)
# [apps.dvwa]
# regression_threshold = 0.08
```

`bench/setup.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail

# bench/ — detector accuracy harness installer (DEV-ONLY, not end users)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== bench setup ==="

# Verify we're in a sqli-recon checkout
if [ ! -f "$REPO_ROOT/pyproject.toml" ]; then
    echo "[-] Run this from inside a sqli-recon checkout."
    exit 1
fi

# Re-use the project venv if it exists (created by top-level setup.sh)
if [ -d "$REPO_ROOT/.venv" ]; then
    echo "[+] Reusing existing venv at $REPO_ROOT/.venv"
    source "$REPO_ROOT/.venv/bin/activate"
else
    echo "[-] No .venv found. Run ./setup.sh in the repo root first."
    exit 1
fi

# Install bench extras (currently just PyYAML)
echo "[+] Installing bench extras..."
pip install -e "$REPO_ROOT[bench]" -q 2>&1 | tail -1

# Verify docker (required for DVWA)
if command -v docker &>/dev/null; then
    echo "[+] Docker found: $(docker --version)"
    echo "[*] Pulling DVWA image (this may take a minute)..."
    docker pull vulnerables/web-dvwa:latest 2>&1 | tail -2
else
    echo "[!] Docker not found — DVWA corpus will be skipped."
    echo "    Install docker to enable: https://docs.docker.com/engine/install/"
fi

echo ""
echo "=== bench setup complete ==="
echo ""
echo "Run: python -m bench"
```

`bench/README.md`:
```markdown
# bench/ — Detector Accuracy Harness

**Audience:** sqli-recon maintainers and contributors. End users never run this.

Measures precision/recall of sqli-recon's detectors against a known-labeled
corpus (currently vulnerable_app + DVWA) so detector changes can be validated
against a persisted baseline.

## Setup (once, on dev machine)

```bash
./setup.sh        # top-level — installs sqli-recon itself
cd bench && ./setup.sh    # bench-specific deps (PyYAML, docker check, DVWA pull)
```

## Usage

```bash
python -m bench                   # run all, exit 0 = pass, exit 1 = regression
python -m bench --detail          # full per-finding breakdown table
python -m bench --apps dvwa       # subset corpus
python -m bench --detectors error # subset detectors
python -m bench --save-baseline   # persist current as new baseline
python -m bench --update-labels   # refresh corpus labels (pull DVWA, re-extract)
python -m bench --layer a         # only run isolated layer (skip end-to-end)
```

See `docs/superpowers/specs/2026-05-17-detector-accuracy-harness-design.md`
for the full design.
```

`tests/bench/__init__.py`: (empty file)

- [ ] **Step 4: Update pyproject.toml**

Add to `[project.optional-dependencies]` section:
```toml
[project.optional-dependencies]
headless = ["playwright>=1.40.0"]
bench = ["pyyaml>=6.0"]
```

- [ ] **Step 5: Update .gitignore**

Append to `.gitignore`:
```
# bench harness runtime artifacts
bench/last_run.log
bench/baseline.json.tmp
```

- [ ] **Step 6: Make setup.sh executable**

```bash
chmod +x ~/projects/sqli-recon/bench/setup.sh
```

- [ ] **Step 7: Run tests to verify they pass**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_smoke.py -v
```
Expected: 2 passed.

- [ ] **Step 8: Commit**

```bash
cd ~/projects/sqli-recon
git add bench/ tests/bench/ pyproject.toml .gitignore
git commit -m "bench: scaffold harness package + smoke tests

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: `Label` dataclass + loader

**Files:**
- Create: `bench/label.py`, `tests/bench/test_label.py`, `tests/bench/fixtures/sample_labels.json`

- [ ] **Step 1: Write the failing tests**

`tests/bench/fixtures/sample_labels.json`:
```json
[
  {
    "app": "vulnerable_app",
    "url_path": "/users",
    "method": "GET",
    "parameter": "id",
    "location": "query",
    "vuln_types": ["sqli"],
    "context": {}
  },
  {
    "app": "vulnerable_app",
    "url_path": "/about",
    "method": "GET",
    "parameter": "",
    "location": "query",
    "vuln_types": [],
    "context": {"note": "clean endpoint, no params"}
  }
]
```

`tests/bench/test_label.py`:
```python
import json
from pathlib import Path

from bench.label import Label, load_labels
from sqli_recon.models import ParamLocation, VulnType

FIXTURE = Path(__file__).parent / "fixtures" / "sample_labels.json"


def test_label_dataclass_fields():
    label = Label(
        app="x", url_path="/", method="GET", parameter="id",
        location=ParamLocation.QUERY, vuln_types=[VulnType.SQLI], context={},
    )
    assert label.app == "x"
    assert label.vuln_types == [VulnType.SQLI]


def test_load_labels_reads_json():
    labels = load_labels(FIXTURE)
    assert len(labels) == 2
    assert labels[0].parameter == "id"
    assert labels[0].vuln_types == [VulnType.SQLI]
    assert labels[1].vuln_types == []  # clean endpoint
    assert labels[1].context["note"] == "clean endpoint, no params"


def test_load_labels_rejects_unknown_vuln_type():
    import pytest
    bad = [{"app": "x", "url_path": "/", "method": "GET", "parameter": "id",
            "location": "query", "vuln_types": ["bogus"], "context": {}}]
    bad_path = FIXTURE.parent / "bad_labels.json"
    bad_path.write_text(json.dumps(bad))
    try:
        with pytest.raises(ValueError, match="bogus"):
            load_labels(bad_path)
    finally:
        bad_path.unlink()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_label.py -v
```
Expected: FAIL — `bench.label` module not found.

- [ ] **Step 3: Implement bench/label.py**

```python
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
    for entry in data:
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
    return labels
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_label.py -v
```
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add bench/label.py tests/bench/test_label.py tests/bench/fixtures/
git commit -m "bench: Label dataclass + JSON loader

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: `score.py` — compare / score / diff_vs_baseline (pure functions)

**Files:**
- Create: `bench/score.py`, `tests/bench/test_score.py`

- [ ] **Step 1: Write the failing tests**

`tests/bench/test_score.py`:
```python
from bench.label import Label
from bench.score import compare, score, diff_vs_baseline
from sqli_recon.models import ParamLocation, VulnType


def _label(app, path, param, vuln_types, method="GET"):
    return Label(app=app, url_path=path, method=method, parameter=param,
                 location=ParamLocation.QUERY, vuln_types=vuln_types, context={})


def test_compare_true_positive():
    labels = [_label("app", "/users", "id", [VulnType.SQLI])]
    # "found" is a dict: detector_name -> set of (url_path, method, param) tuples it confirmed
    found = {"ErrorDetector": {("/users", "GET", "id")}}
    result = compare(found, labels)
    assert result["ErrorDetector"] == {"tp": 1, "fp": 0, "fn": 0}


def test_compare_false_positive():
    labels = [_label("app", "/about", "id", [])]  # not vulnerable
    found = {"ErrorDetector": {("/about", "GET", "id")}}
    result = compare(found, labels)
    assert result["ErrorDetector"] == {"tp": 0, "fp": 1, "fn": 0}


def test_compare_false_negative():
    labels = [_label("app", "/users", "id", [VulnType.SQLI])]
    found = {"ErrorDetector": set()}
    result = compare(found, labels)
    assert result["ErrorDetector"] == {"tp": 0, "fp": 0, "fn": 1}


def test_compare_multiple_detectors():
    labels = [
        _label("app", "/users", "id", [VulnType.SQLI]),
        _label("app", "/render", "tpl", [VulnType.SSTI]),
    ]
    found = {
        "ErrorDetector": {("/users", "GET", "id")},
        "SSTIDetector": {("/render", "GET", "tpl")},
    }
    result = compare(found, labels)
    assert result["ErrorDetector"] == {"tp": 1, "fp": 0, "fn": 0}
    assert result["SSTIDetector"] == {"tp": 1, "fp": 0, "fn": 0}


def test_compare_finding_outside_labels_logged_not_counted():
    """Findings on unlabeled endpoints don't count (no ground truth)."""
    labels = [_label("app", "/users", "id", [VulnType.SQLI])]
    found = {"ErrorDetector": {("/users", "GET", "id"),
                                ("/unknown", "GET", "x")}}  # /unknown not labeled
    result = compare(found, labels)
    # The /unknown finding is dropped; only /users counts as TP
    assert result["ErrorDetector"] == {"tp": 1, "fp": 0, "fn": 0}


def test_score_precision_recall_f1():
    comparison = {"ErrorDetector": {"tp": 8, "fp": 2, "fn": 1}}
    result = score(comparison)
    # precision = 8/(8+2) = 0.8
    # recall    = 8/(8+1) = 0.889
    # f1        = 2*0.8*0.889 / (0.8+0.889) = 0.842
    assert abs(result["ErrorDetector"]["precision"] - 0.8) < 0.01
    assert abs(result["ErrorDetector"]["recall"] - 0.889) < 0.01
    assert abs(result["ErrorDetector"]["f1"] - 0.842) < 0.01


def test_score_zero_division_safe():
    """No labels and no findings → all zero, no crash."""
    comparison = {"ErrorDetector": {"tp": 0, "fp": 0, "fn": 0}}
    result = score(comparison)
    assert result["ErrorDetector"] == {"precision": 0.0, "recall": 0.0, "f1": 0.0}


def test_diff_vs_baseline_no_regression():
    baseline = {"app": {"ErrorDetector": {"isolated": {"precision": 0.9, "recall": 0.8, "f1": 0.85}}}}
    current = {"app": {"ErrorDetector": {"isolated": {"precision": 0.92, "recall": 0.81, "f1": 0.86}}}}
    regressions = diff_vs_baseline(current, baseline, threshold=0.05)
    assert regressions == []


def test_diff_vs_baseline_detects_regression():
    baseline = {"app": {"ErrorDetector": {"isolated": {"precision": 0.9, "recall": 0.8, "f1": 0.85}}}}
    current = {"app": {"ErrorDetector": {"isolated": {"precision": 0.6, "recall": 0.8, "f1": 0.69}}}}
    regressions = diff_vs_baseline(current, baseline, threshold=0.05)
    assert len(regressions) >= 1
    assert any("precision" in r["metric"] for r in regressions)
    assert any(r["app"] == "app" for r in regressions)


def test_diff_vs_baseline_missing_keys_safe():
    """New detector not in baseline = no regression (just informational)."""
    baseline = {"app": {"ErrorDetector": {"isolated": {"precision": 0.9, "recall": 0.8, "f1": 0.85}}}}
    current = {"app": {
        "ErrorDetector": {"isolated": {"precision": 0.9, "recall": 0.8, "f1": 0.85}},
        "NewDetector":   {"isolated": {"precision": 0.5, "recall": 0.5, "f1": 0.5}},
    }}
    regressions = diff_vs_baseline(current, baseline, threshold=0.05)
    assert regressions == []
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_score.py -v
```
Expected: FAIL — `bench.score` module not found.

- [ ] **Step 3: Implement bench/score.py**

```python
"""Pure scoring functions. See spec section 6.3.

compare(): findings vs labels → per-detector TP/FP/FN counts
score():   counts → precision/recall/f1
diff_vs_baseline(): current scores vs prior baseline → regressions
"""
from typing import Dict, List, Set, Tuple

from bench.label import Label
from sqli_recon.models import VulnType


# Which VulnType each detector confirms — used to attribute Layer B findings
DETECTOR_VULN_TYPE = {
    "ErrorDetector": VulnType.SQLI,
    "SSTIDetector": VulnType.SSTI,
    "CommandInjectionDetector": VulnType.CMDI,
    "HeaderInjectionScanner": VulnType.SQLI,  # also detects SQLi (via headers)
}


def compare(
    found: Dict[str, Set[Tuple[str, str, str]]],
    labels: List[Label],
) -> Dict[str, Dict[str, int]]:
    """
    Compare per-detector findings to labeled ground truth.

    Args:
        found: detector_name -> set of (url_path, method, parameter) confirmed
        labels: list of Label objects (ground truth)

    Returns:
        detector_name -> {"tp": N, "fp": N, "fn": N}

    Findings on endpoints not in labels are dropped (no ground truth).
    Findings on endpoints in labels but where vuln_types doesn't include
    the detector's vuln_type count as false positives.
    """
    # Build label lookup: (path, method, param) -> set of vuln_types
    label_index = {}
    for lab in labels:
        key = (lab.url_path, lab.method, lab.parameter)
        label_index[key] = set(lab.vuln_types)

    result = {}
    for detector_name, found_set in found.items():
        expected_vuln_type = DETECTOR_VULN_TYPE.get(detector_name)
        tp = fp = fn = 0

        # Walk findings → TP / FP / drop-if-no-ground-truth
        for finding_key in found_set:
            if finding_key not in label_index:
                continue  # No ground truth, skip
            label_vuln_types = label_index[finding_key]
            if expected_vuln_type in label_vuln_types:
                tp += 1
            else:
                fp += 1

        # Walk labels → FN (labeled vuln that wasn't found)
        for label_key, vuln_types in label_index.items():
            if expected_vuln_type in vuln_types and label_key not in found_set:
                fn += 1

        result[detector_name] = {"tp": tp, "fp": fp, "fn": fn}

    return result


def score(comparison: Dict[str, Dict[str, int]]) -> Dict[str, Dict[str, float]]:
    """Convert TP/FP/FN counts to precision/recall/F1."""
    result = {}
    for detector_name, counts in comparison.items():
        tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)
              if (precision + recall) > 0 else 0.0)
        result[detector_name] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }
    return result


def diff_vs_baseline(
    current: Dict[str, Dict[str, Dict[str, Dict[str, float]]]],
    baseline: Dict[str, Dict[str, Dict[str, Dict[str, float]]]],
    threshold: float = 0.05,
) -> List[Dict]:
    """
    Compare current scores to baseline, return regressions.

    Structure: {app -> {detector -> {layer -> {metric -> value}}}}
    A regression is any metric drop > threshold.
    New detectors/apps in current but not baseline are informational only.

    Returns list of dicts: [{"app", "detector", "layer", "metric", "baseline", "current", "delta"}]
    """
    regressions = []
    for app, app_scores in current.items():
        baseline_app = baseline.get(app, {})
        for detector, detector_scores in app_scores.items():
            baseline_detector = baseline_app.get(detector, {})
            for layer, layer_scores in detector_scores.items():
                baseline_layer = baseline_detector.get(layer, {})
                for metric, value in layer_scores.items():
                    baseline_value = baseline_layer.get(metric)
                    if baseline_value is None:
                        continue  # New — not a regression
                    delta = value - baseline_value
                    if delta < -threshold:
                        regressions.append({
                            "app": app,
                            "detector": detector,
                            "layer": layer,
                            "metric": metric,
                            "baseline": baseline_value,
                            "current": value,
                            "delta": delta,
                        })
    return regressions
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_score.py -v
```
Expected: 9 passed.

- [ ] **Step 5: Commit**

```bash
git add bench/score.py tests/bench/test_score.py
git commit -m "bench: pure compare/score/diff_vs_baseline functions

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Annotate `tests/vulnerable_app.py` + write extractor

**Files:**
- Modify: `tests/vulnerable_app.py` (add `# VULN:` annotations)
- Create: `bench/corpus/vulnerable_app/extractor.py`, `tests/bench/test_vulnerable_app_extractor.py`

- [ ] **Step 1: Inspect existing vulnerable_app to identify vulnerable views**

```bash
cd ~/projects/sqli-recon && grep -n '@app.route' tests/vulnerable_app.py
```
Note the route paths. The next step adds annotations.

- [ ] **Step 2: Add `# VULN:` annotations to vulnerable_app**

For each known-vulnerable view in `tests/vulnerable_app.py`, add a single-line annotation directly above the `@app.route(...)` decorator. Format:

```python
# VULN: vuln_type=sqli, param=q, location=query
@app.route("/search")
def search():
    q = request.args.get("q", "")
    cur.execute(f"SELECT * FROM items WHERE name LIKE '%{q}%'")  # known SQLi
```

For clean endpoints (no vuln), add:

```python
# VULN: clean
@app.route("/about")
def about():
    return "About page"
```

Annotation grammar (one annotation per route handler):
- `# VULN: vuln_type=<sqli|ssti|cmdi>, param=<name>, location=<query|body|json|path|header>` — vulnerable
- `# VULN: clean` — explicitly clean (so harness knows it's been considered)

Multiple vuln types on same endpoint: separate annotations or comma-list — use comma-list:
```python
# VULN: vuln_type=sqli, param=id, location=query
# VULN: vuln_type=ssti, param=tpl, location=body
@app.route("/multi", methods=["POST"])
```

- [ ] **Step 3: Write the extractor failing test**

`tests/bench/test_vulnerable_app_extractor.py`:
```python
from pathlib import Path

from bench.corpus.vulnerable_app.extractor import extract
from sqli_recon.models import ParamLocation, VulnType


def test_extract_finds_annotated_vuln():
    labels = extract()
    assert len(labels) > 0
    # All labels should be tagged with app="vulnerable_app"
    assert all(lab.app == "vulnerable_app" for lab in labels)


def test_extract_distinguishes_clean_endpoints():
    labels = extract()
    clean = [lab for lab in labels if not lab.vuln_types]
    assert len(clean) >= 1, "expected at least one explicitly-clean endpoint"


def test_extract_at_least_one_sqli():
    labels = extract()
    sqli_labels = [lab for lab in labels if VulnType.SQLI in lab.vuln_types]
    assert len(sqli_labels) >= 1


def test_extract_resolves_query_location():
    labels = extract()
    has_query = any(lab.location == ParamLocation.QUERY for lab in labels)
    assert has_query
```

- [ ] **Step 4: Run test to verify it fails**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_vulnerable_app_extractor.py -v
```
Expected: FAIL — extractor module not found.

- [ ] **Step 5: Implement the extractor**

`bench/corpus/__init__.py` (empty file):
```bash
touch ~/projects/sqli-recon/bench/corpus/__init__.py
touch ~/projects/sqli-recon/bench/corpus/vulnerable_app/__init__.py
```

`bench/corpus/vulnerable_app/extractor.py`:
```python
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

    # Walk lines, collect contiguous `# VULN:` annotations, then the next
    # @app.route line gives the path.
    pending_annotations = []
    for line in lines:
        stripped = line.strip()

        # Reset when we see a non-comment, non-route line
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
            # Naive parse — methods like '"POST", "PUT"' → ["POST", "PUT"]
            methods = [s.strip().strip("'\"") for s in methods_str.split(",")]
            if not methods:
                methods = ["GET"]

            # Special case: single "clean" annotation → one label per method, empty vuln_types
            if any(a.get("clean") for a in pending_annotations):
                for method in methods:
                    labels.append(Label(
                        app="vulnerable_app", url_path=path, method=method,
                        parameter="", location=ParamLocation.QUERY,
                        vuln_types=[], context={},
                    ))
            else:
                # One label per (annotation × method)
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
            # Non-route, non-comment line — drop pending unless it's a decorator continuation
            if not stripped.startswith("@") and stripped and not stripped.startswith('"""'):
                pending_annotations = []

    return labels
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_vulnerable_app_extractor.py -v
```
Expected: 4 passed (assuming you annotated at least one vuln, one clean, and one query param in Step 2).

- [ ] **Step 7: Generate the initial labels.json**

```bash
cd ~/projects/sqli-recon && python -c "
import json
from bench.corpus.vulnerable_app.extractor import extract
from dataclasses import asdict
labels = extract()
data = []
for lab in labels:
    d = asdict(lab)
    d['location'] = d['location'].value
    d['vuln_types'] = [v.value for v in d['vuln_types']]
    data.append(d)
with open('bench/corpus/vulnerable_app/labels.json', 'w') as f:
    json.dump(data, f, indent=2)
print(f'Wrote {len(data)} labels')
"
cat bench/corpus/vulnerable_app/labels.json | head -30
```

- [ ] **Step 8: Commit**

```bash
git add tests/vulnerable_app.py bench/corpus/ tests/bench/test_vulnerable_app_extractor.py
git commit -m "bench: annotate vulnerable_app + extractor

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: `corpus.py` — app discovery + app.yaml loader

**Files:**
- Create: `bench/corpus.py`, `tests/bench/test_corpus.py`, `tests/bench/fixtures/sample_app.yaml`, `bench/corpus/vulnerable_app/app.yaml`

- [ ] **Step 1: Create vulnerable_app's app.yaml**

`bench/corpus/vulnerable_app/app.yaml`:
```yaml
name: vulnerable_app
kind: process
command: ["python", "tests/vulnerable_app.py"]
port: 18484
healthcheck:
  url: http://127.0.0.1:18484/
  timeout: 15
setup: []
teardown: []
```

- [ ] **Step 2: Create fixture**

`tests/bench/fixtures/sample_app.yaml`:
```yaml
name: testapp
kind: docker
image: example/test:latest
port: 8080
healthcheck:
  url: http://127.0.0.1:8080/health
  timeout: 30
setup:
  - {http: POST, path: /admin/reset}
teardown: []
```

- [ ] **Step 3: Write failing tests**

`tests/bench/test_corpus.py`:
```python
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
    assert cfg.command == ["python", "tests/vulnerable_app.py"]


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
```

- [ ] **Step 4: Run tests to verify they fail**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_corpus.py -v
```
Expected: FAIL — `bench.corpus` not found.

- [ ] **Step 5: Implement bench/corpus.py**

```python
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
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_corpus.py -v
```
Expected: 4 passed.

- [ ] **Step 7: Commit**

```bash
git add bench/corpus.py bench/corpus/vulnerable_app/app.yaml tests/bench/test_corpus.py tests/bench/fixtures/sample_app.yaml
git commit -m "bench: corpus app discovery + app.yaml loader

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: `lifecycle.py` — ProcessApp + DockerApp managers

**Files:**
- Create: `bench/lifecycle.py`, `tests/bench/test_lifecycle.py`

- [ ] **Step 1: Write failing tests**

`tests/bench/test_lifecycle.py`:
```python
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
        # Healthcheck already passed inside __enter__
        assert handle.base_url.endswith(":18484")
        # Verify it actually answers
        resp = requests.get(handle.base_url, timeout=5)
        assert resp.status_code in (200, 404)  # 404 ok — depends on the app's root route

    # After __exit__, process should be gone
    time.sleep(0.2)
    with pytest.raises(requests.exceptions.ConnectionError):
        requests.get("http://127.0.0.1:18484/", timeout=2)


def test_app_for_config_dispatches_on_kind():
    cfg = load_app_config(REPO_ROOT / "bench" / "corpus" / "vulnerable_app" / "app.yaml")
    app = app_for_config(cfg, cwd=REPO_ROOT)
    assert isinstance(app, ProcessApp)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_lifecycle.py -v
```
Expected: FAIL — `bench.lifecycle` not found.

- [ ] **Step 3: Implement bench/lifecycle.py**

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_lifecycle.py -v
```
Expected: 2 passed. If vulnerable_app.py needs `requests` or other deps, install them first.

- [ ] **Step 5: Commit**

```bash
git add bench/lifecycle.py tests/bench/test_lifecycle.py
git commit -m "bench: ProcessApp + DockerApp lifecycle managers

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: `detector_runner.py` — Layer A (per-detector synthetic invocation)

**Files:**
- Create: `bench/detector_runner.py`, `tests/bench/test_detector_runner.py`

- [ ] **Step 1: Write failing tests**

`tests/bench/test_detector_runner.py`:
```python
from unittest.mock import MagicMock

from bench.detector_runner import build_synthetic_finding, run_layer_a
from bench.label import Label
from sqli_recon.models import ParamLocation, VulnType


def _label(path, param, location, vt):
    return Label(app="x", url_path=path, method="GET", parameter=param,
                 location=location, vuln_types=[vt] if vt else [], context={})


def test_build_synthetic_finding_query():
    lab = _label("/users", "id", ParamLocation.QUERY, VulnType.SQLI)
    f = build_synthetic_finding(lab, base_url="http://x:8080")
    assert f.endpoint.url.startswith("http://x:8080/users")
    assert f.parameter.name == "id"
    assert f.score == 1.0  # passes any min_score filter


def test_build_synthetic_finding_body():
    lab = _label("/login", "password", ParamLocation.BODY, VulnType.SQLI)
    f = build_synthetic_finding(lab, base_url="http://x:8080")
    assert f.parameter.location == ParamLocation.BODY


def test_run_layer_a_reports_per_detector(monkeypatch):
    """Layer A invokes each detector on each label, returns per-detector found-set."""
    labels = [_label("/users", "id", ParamLocation.QUERY, VulnType.SQLI)]

    # Mock the detector classes to return "confirmed" for every input
    fake_confirmed = [(MagicMock(endpoint=MagicMock(url="http://x:8080/users"),
                                 parameter=MagicMock(name="id")), "MySQL")]
    from sqli_recon.intelligence import ErrorDetector
    monkeypatch.setattr(ErrorDetector, "test_findings",
                        lambda self, findings, **kw: fake_confirmed if findings else [])

    # Also mock the other detectors to return empty
    from sqli_recon.intelligence import SSTIDetector, CommandInjectionDetector
    monkeypatch.setattr(SSTIDetector, "test_findings", lambda *a, **kw: [])
    monkeypatch.setattr(CommandInjectionDetector, "test_findings", lambda *a, **kw: [])

    client = MagicMock()
    found = run_layer_a(labels, base_url="http://x:8080", client=client)
    assert "ErrorDetector" in found
    assert ("/users", "GET", "id") in found["ErrorDetector"]
    # SSTI/CmdI not confirmed
    assert found["SSTIDetector"] == set()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_detector_runner.py -v
```
Expected: FAIL — `bench.detector_runner` not found.

- [ ] **Step 3: Implement bench/detector_runner.py**

```python
"""Layer A: invoke each detector class directly on synthetic Findings.

For each label in the corpus, construct a Finding object referring to that
endpoint+parameter, then invoke each detector. Records which (path, method,
param) tuples each detector confirmed.
"""
from typing import Dict, List, Set, Tuple
from urllib.parse import urljoin

from bench.label import Label
from sqli_recon.http_client import HttpClient
from sqli_recon.intelligence import (
    ErrorDetector,
    SSTIDetector,
    CommandInjectionDetector,
)
from sqli_recon.models import Endpoint, Parameter, Finding, ParamLocation


def build_synthetic_finding(label: Label, base_url: str) -> Finding:
    """Construct a Finding for an arbitrary label, suitable for direct detector invocation."""
    # Build a realistic-looking URL for this label
    url = urljoin(base_url + "/", label.url_path.lstrip("/"))
    # Default sample value per param type
    sample_value = "1" if label.location == ParamLocation.PATH else "test"
    if label.location == ParamLocation.QUERY and label.parameter:
        url = f"{url}?{label.parameter}={sample_value}"

    param = Parameter(
        name=label.parameter or "_",
        location=label.location,
        value=sample_value,
        param_type="string",
    )
    endpoint = Endpoint(
        url=url, method=label.method,
        parameters=[param],
        content_type="application/json" if label.location == ParamLocation.JSON else "",
    )
    return Finding(endpoint=endpoint, parameter=param, score=1.0)


DETECTOR_CLASSES = [
    ("ErrorDetector", ErrorDetector),
    ("SSTIDetector", SSTIDetector),
    ("CommandInjectionDetector", CommandInjectionDetector),
]


def run_layer_a(
    labels: List[Label],
    base_url: str,
    client: HttpClient,
    detector_filter: List[str] = None,
) -> Dict[str, Set[Tuple[str, str, str]]]:
    """
    Invoke each detector class on synthetic Findings built from labels.

    Returns: detector_name -> set of (url_path, method, parameter) that the
    detector confirmed as injectable.
    """
    findings = [build_synthetic_finding(lab, base_url) for lab in labels]
    found: Dict[str, Set[Tuple[str, str, str]]] = {}

    for detector_name, cls in DETECTOR_CLASSES:
        if detector_filter and not any(f.lower() in detector_name.lower()
                                       for f in detector_filter):
            continue
        detector = cls(client)
        confirmed_pairs = detector.test_findings(findings, min_score=0.0)
        # confirmed_pairs: list of (finding, detail). Extract the keys.
        key_set = set()
        for finding, _detail in confirmed_pairs:
            # Map finding's URL back to its label's url_path
            for lab in labels:
                lab_url = urljoin(base_url + "/", lab.url_path.lstrip("/"))
                if finding.endpoint.url.startswith(lab_url) and \
                   finding.parameter.name == (lab.parameter or "_"):
                    key_set.add((lab.url_path, lab.method, lab.parameter))
                    break
        found[detector_name] = key_set

    return found
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_detector_runner.py -v
```
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add bench/detector_runner.py tests/bench/test_detector_runner.py
git commit -m "bench: Layer A per-detector synthetic invocation

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: `e2e_runner.py` — Layer B (end-to-end scan invocation)

**Files:**
- Create: `bench/e2e_runner.py`, `tests/bench/test_e2e_runner.py`

- [ ] **Step 1: Write failing tests**

`tests/bench/test_e2e_runner.py`:
```python
from unittest.mock import patch, MagicMock

from bench.e2e_runner import run_layer_b


def test_run_layer_b_groups_by_confirmed_type(monkeypatch):
    """Layer B parses the scan's findings into per-detector found-sets."""
    # Simulate a scan producing 2 findings:
    #  - SQLi-confirmed at /users?id=
    #  - SSTI-confirmed at /render?tpl=
    from sqli_recon.models import Endpoint, Parameter, Finding, ParamLocation, VulnType

    f1 = Finding(
        endpoint=Endpoint(url="http://x:8080/users?id=1", method="GET",
                          parameters=[Parameter("id", ParamLocation.QUERY, "1")]),
        parameter=Parameter("id", ParamLocation.QUERY, "1"),
        score=0.95,
        confirmed_types={VulnType.SQLI},
    )
    f2 = Finding(
        endpoint=Endpoint(url="http://x:8080/render?tpl=hi", method="GET",
                          parameters=[Parameter("tpl", ParamLocation.QUERY, "hi")]),
        parameter=Parameter("tpl", ParamLocation.QUERY, "hi"),
        score=0.95,
        confirmed_types={VulnType.SSTI},
    )

    monkeypatch.setattr("bench.e2e_runner._invoke_scan", lambda *a, **kw: [f1, f2])

    found = run_layer_b(base_url="http://x:8080")
    # ErrorDetector confirms SQLI → should pick up f1
    assert ("/users", "GET", "id") in found["ErrorDetector"]
    # SSTIDetector confirms SSTI → should pick up f2
    assert ("/render", "GET", "tpl") in found["SSTIDetector"]
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_e2e_runner.py -v
```
Expected: FAIL — `bench.e2e_runner` not found.

- [ ] **Step 3: Implement bench/e2e_runner.py**

```python
"""Layer B: invoke sqli-recon's full scan pipeline against a corpus app.

Captures the resulting Findings (with their confirmed_types populated by
detectors), groups by detector, and returns the same shape as Layer A.
"""
import tempfile
from pathlib import Path
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

from sqli_recon.models import Finding, VulnType
from bench.score import DETECTOR_VULN_TYPE


def _invoke_scan(base_url: str, output_dir: Path) -> List[Finding]:
    """
    Run sqli_recon.cli.main against base_url. Returns the list of Findings.

    Implementation: run a minimal in-process scan rather than shelling out,
    so we can grab the Finding list directly.
    """
    # Import locally to avoid importing the CLI at module load time
    from sqli_recon.http_client import HttpClient
    from sqli_recon.crawler import Crawler
    from sqli_recon.js_analyzer import JsAnalyzer
    from sqli_recon.classifier import Classifier
    from sqli_recon.intelligence import (
        ErrorDetector, SSTIDetector, CommandInjectionDetector,
    )

    client = HttpClient(timeout=10, rate_limit=0.0)
    crawler = Crawler(client=client, target_url=base_url, max_depth=2, max_pages=50)
    endpoints, js_urls = crawler.crawl()
    if js_urls:
        analyzer = JsAnalyzer(client, base_url)
        endpoints.extend(analyzer.analyze(js_urls))

    findings = Classifier().classify(endpoints)

    # Run each detector to populate confirmed_types
    for detector_cls, vuln_type in [
        (ErrorDetector, VulnType.SQLI),
        (SSTIDetector, VulnType.SSTI),
        (CommandInjectionDetector, VulnType.CMDI),
    ]:
        confirmed = detector_cls(client).test_findings(findings, min_score=0.3)
        for finding, _detail in confirmed:
            finding.confirmed_types.add(vuln_type)

    return findings


def run_layer_b(
    base_url: str,
    detector_filter: List[str] = None,
) -> Dict[str, Set[Tuple[str, str, str]]]:
    """
    Run a full sqli-recon scan against base_url, group findings by detector.

    Returns same shape as Layer A: detector_name -> set of (url_path, method, parameter).
    """
    with tempfile.TemporaryDirectory() as tmp:
        findings = _invoke_scan(base_url, Path(tmp))

    found: Dict[str, Set[Tuple[str, str, str]]] = {}
    for detector_name, expected_vuln_type in DETECTOR_VULN_TYPE.items():
        if detector_filter and not any(f.lower() in detector_name.lower()
                                       for f in detector_filter):
            continue
        key_set = set()
        for finding in findings:
            if expected_vuln_type in finding.confirmed_types:
                path = urlparse(finding.endpoint.url).path
                key_set.add((path, finding.endpoint.method, finding.parameter.name))
        found[detector_name] = key_set

    return found
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_e2e_runner.py -v
```
Expected: 1 passed.

- [ ] **Step 5: Commit**

```bash
git add bench/e2e_runner.py tests/bench/test_e2e_runner.py
git commit -m "bench: Layer B end-to-end scan invocation

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: `runner.py` — orchestration + first integration test

**Files:**
- Create: `bench/runner.py`, `tests/bench/test_integration.py`

- [ ] **Step 1: Write integration test (uses real vulnerable_app)**

`tests/bench/test_integration.py`:
```python
import pytest
from pathlib import Path

from bench.runner import run_for_app
from bench.corpus import load_app_config

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.integration
def test_run_for_vulnerable_app():
    """Full harness against the real vulnerable_app. Slow."""
    cfg = load_app_config(REPO_ROOT / "bench" / "corpus" / "vulnerable_app" / "app.yaml")
    scores = run_for_app(cfg, layer="both", cwd=REPO_ROOT)

    assert "vulnerable_app" in scores
    detector_scores = scores["vulnerable_app"]
    # At minimum, ErrorDetector should produce a number for both layers
    assert "ErrorDetector" in detector_scores
    assert "isolated" in detector_scores["ErrorDetector"]
    assert "end_to_end" in detector_scores["ErrorDetector"]
    # Should find at least one SQLi (the known vulns in vulnerable_app)
    isolated_recall = detector_scores["ErrorDetector"]["isolated"]["recall"]
    assert isolated_recall > 0, "ErrorDetector should find at least one known SQLi via Layer A"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_integration.py -v -m integration
```
Expected: FAIL — `bench.runner` not found.

- [ ] **Step 3: Implement bench/runner.py**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_integration.py -v -m integration
```
Expected: 1 passed (may take 30-60s for the scan to complete).

- [ ] **Step 5: Commit**

```bash
git add bench/runner.py tests/bench/test_integration.py
git commit -m "bench: orchestration runner + vulnerable_app integration test

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: DVWA corpus — app.yaml + extractor + labels

**Files:**
- Create: `bench/corpus/dvwa/__init__.py`, `bench/corpus/dvwa/app.yaml`, `bench/corpus/dvwa/extractor.py`, `bench/corpus/dvwa/labels.json`, `tests/bench/test_dvwa_extractor.py`

- [ ] **Step 1: Create app.yaml for DVWA**

`bench/corpus/dvwa/app.yaml`:
```yaml
name: dvwa
kind: docker
image: vulnerables/web-dvwa:latest
port: 8080
healthcheck:
  url: http://127.0.0.1:8080/login.php
  timeout: 60
setup:
  - {http: GET, path: /setup.php}
  - {http: POST, path: /setup.php, data: {create_db: "Create / Reset Database"}}
  # NOTE: Login + security-level setting happens at scan time, not in app.yaml,
  # because it requires cookie capture which app.yaml's simple HTTP steps can't do.
  # See bench/corpus/dvwa/extractor.py for the DVWA-specific session bootstrap.
teardown: []
```

- [ ] **Step 2: Write failing extractor test**

`tests/bench/test_dvwa_extractor.py`:
```python
from bench.corpus.dvwa.extractor import extract
from sqli_recon.models import ParamLocation, VulnType


def test_extract_returns_labels():
    labels = extract()
    assert len(labels) > 0
    assert all(lab.app == "dvwa" for lab in labels)


def test_extract_finds_sqli():
    labels = extract()
    sqli = [lab for lab in labels if VulnType.SQLI in lab.vuln_types]
    assert len(sqli) >= 1
    # The classic /vulnerabilities/sqli/ endpoint with id param
    assert any(lab.url_path == "/vulnerabilities/sqli/" and lab.parameter == "id"
               for lab in sqli)


def test_extract_finds_cmdi():
    labels = extract()
    cmdi = [lab for lab in labels if VulnType.CMDI in lab.vuln_types]
    assert len(cmdi) >= 1
```

- [ ] **Step 3: Run test to verify it fails**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_dvwa_extractor.py -v
```
Expected: FAIL — extractor not found.

- [ ] **Step 4: Implement DVWA extractor**

`bench/corpus/dvwa/__init__.py`: (empty)

`bench/corpus/dvwa/extractor.py`:
```python
"""Static label map for DVWA. The vulnerability set is stable across releases."""
from typing import List

from bench.label import Label
from sqli_recon.models import ParamLocation, VulnType


# DVWA's vulnerability pages — these are stable across versions.
# Each entry: (path, method, parameter, location, vuln_types, context)
DVWA_VULN_MAP = [
    # SQL Injection
    ("/vulnerabilities/sqli/",       "GET",  "id", ParamLocation.QUERY,
     [VulnType.SQLI], {"category": "sqli"}),
    ("/vulnerabilities/sqli_blind/", "GET",  "id", ParamLocation.QUERY,
     [VulnType.SQLI], {"category": "sqli_blind"}),

    # Command Injection
    ("/vulnerabilities/exec/", "POST", "ip", ParamLocation.BODY,
     [VulnType.CMDI], {"category": "exec"}),

    # Clean endpoints (DVWA static pages, no vuln)
    ("/index.php",        "GET", "", ParamLocation.QUERY, [], {"clean": True}),
    ("/about.php",        "GET", "", ParamLocation.QUERY, [], {"clean": True}),
    ("/instructions.php", "GET", "", ParamLocation.QUERY, [], {"clean": True}),
]


def extract() -> List[Label]:
    """Return DVWA labels. Map is static — DVWA's vuln set is stable."""
    labels = []
    for path, method, param, location, vuln_types, context in DVWA_VULN_MAP:
        labels.append(Label(
            app="dvwa", url_path=path, method=method, parameter=param,
            location=location, vuln_types=vuln_types, context=context,
        ))
    return labels
```

- [ ] **Step 5: Run test to verify it passes**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_dvwa_extractor.py -v
```
Expected: 3 passed.

- [ ] **Step 6: Generate the initial DVWA labels.json**

```bash
cd ~/projects/sqli-recon && python -c "
import json
from dataclasses import asdict
from bench.corpus.dvwa.extractor import extract
labels = extract()
data = []
for lab in labels:
    d = asdict(lab)
    d['location'] = d['location'].value
    d['vuln_types'] = [v.value for v in d['vuln_types']]
    data.append(d)
with open('bench/corpus/dvwa/labels.json', 'w') as f:
    json.dump(data, f, indent=2)
print(f'Wrote {len(data)} DVWA labels')
"
```

- [ ] **Step 7: Commit**

```bash
git add bench/corpus/dvwa/ tests/bench/test_dvwa_extractor.py
git commit -m "bench: DVWA corpus app config + static label map

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: DVWA session bootstrap (login + security-level cookie)

DVWA requires login before any vulnerability page is accessible. The default credentials are admin/password. Additionally, the "security level" cookie controls whether vulns are exploitable — must be set to `low`.

**Files:**
- Modify: `bench/runner.py` (add DVWA-aware session bootstrap)
- Create: `bench/corpus/dvwa/bootstrap.py`

- [ ] **Step 1: Write failing test**

Append to `tests/bench/test_integration.py`:
```python
@pytest.mark.integration
@pytest.mark.dvwa
def test_run_for_dvwa():
    """Full harness against DVWA in docker. Requires docker + DVWA image pre-pulled."""
    import shutil
    if not shutil.which("docker"):
        pytest.skip("docker not installed")
    cfg = load_app_config(REPO_ROOT / "bench" / "corpus" / "dvwa" / "app.yaml")
    scores = run_for_app(cfg, layer="a", cwd=REPO_ROOT)  # Layer A only for speed

    assert "dvwa" in scores
    assert "ErrorDetector" in scores["dvwa"]
    # Should find sqli on /vulnerabilities/sqli/ with id param
    isolated_recall = scores["dvwa"]["ErrorDetector"]["isolated"]["recall"]
    assert isolated_recall > 0
```

- [ ] **Step 2: Implement DVWA bootstrap**

`bench/corpus/dvwa/bootstrap.py`:
```python
"""DVWA-specific session bootstrap: login + set security=low."""
import logging

from bs4 import BeautifulSoup

log = logging.getLogger(__name__)


def bootstrap_session(client, base_url: str) -> bool:
    """
    Log into DVWA as admin/password and set security level to 'low'.
    Mutates the client's session cookies. Returns True on success.
    """
    # GET login page to capture CSRF token
    resp = client.get(f"{base_url}/login.php")
    if resp is None or resp.status_code != 200:
        log.warning("DVWA login page unreachable")
        return False

    soup = BeautifulSoup(resp.text, "html.parser")
    token_input = soup.find("input", {"name": "user_token"})
    user_token = token_input["value"] if token_input else ""

    # POST credentials
    resp = client.post(
        f"{base_url}/login.php",
        data={
            "username": "admin",
            "password": "password",
            "Login": "Login",
            "user_token": user_token,
        },
    )
    if resp is None or "Login failed" in (resp.text or ""):
        log.warning("DVWA login failed")
        return False

    # Set security cookie to low
    client.session.cookies.set("security", "low")
    log.info("DVWA session bootstrapped (security=low)")
    return True
```

- [ ] **Step 3: Wire bootstrap into runner**

Modify `bench/runner.py` — inside `run_for_app`, after the `with app_for_config(...)` block opens but before the client is created, add:

```python
    with app_for_config(config, cwd=cwd) as handle:
        client = HttpClient(timeout=10, rate_limit=0.0)

        # App-specific session bootstrap if applicable
        if config.name == "dvwa":
            from bench.corpus.dvwa.bootstrap import bootstrap_session
            if not bootstrap_session(client, handle.base_url):
                log.error("DVWA session bootstrap failed — results will be unreliable")
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_integration.py::test_run_for_dvwa -v -m integration
```
Expected: 1 passed (slow — docker pull + container start + scan takes a minute).

If docker not installed or image not pulled: test skips. To pre-pull: `docker pull vulnerables/web-dvwa:latest`.

- [ ] **Step 5: Commit**

```bash
git add bench/corpus/dvwa/bootstrap.py bench/runner.py tests/bench/test_integration.py
git commit -m "bench: DVWA session bootstrap (login + security=low)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 12: `report.py` — pass/fail summary + --detail table

**Files:**
- Create: `bench/report.py`, `tests/bench/test_report.py`

- [ ] **Step 1: Write failing tests**

`tests/bench/test_report.py`:
```python
from bench.report import render_summary, render_detail_table


SAMPLE_SCORES = {
    "vulnerable_app": {
        "ErrorDetector": {
            "isolated":  {"precision": 1.0, "recall": 0.85, "f1": 0.92},
            "end_to_end": {"precision": 0.9, "recall": 0.80, "f1": 0.85},
        },
        "SSTIDetector": {
            "isolated":  {"precision": 0.9, "recall": 0.75, "f1": 0.82},
            "end_to_end": {"precision": 0.8, "recall": 0.70, "f1": 0.75},
        },
    },
}


def test_render_summary_no_regressions():
    out = render_summary(SAMPLE_SCORES, regressions=[])
    assert "PASS" in out
    assert "vulnerable_app" in out


def test_render_summary_with_regressions():
    regs = [{"app": "vulnerable_app", "detector": "ErrorDetector",
             "layer": "isolated", "metric": "recall",
             "baseline": 0.95, "current": 0.85, "delta": -0.10}]
    out = render_summary(SAMPLE_SCORES, regressions=regs)
    assert "FAIL" in out or "REGRESSION" in out
    assert "ErrorDetector" in out
    assert "0.10" in out or "10%" in out or "-0.1" in out


def test_render_detail_table_includes_metrics():
    out = render_detail_table(SAMPLE_SCORES)
    assert "ErrorDetector" in out
    assert "SSTIDetector" in out
    assert "isolated" in out
    assert "end_to_end" in out
    # Numbers should appear
    assert "0.85" in out or "0.8500" in out
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_report.py -v
```
Expected: FAIL — `bench.report` not found.

- [ ] **Step 3: Implement bench/report.py**

```python
"""Render harness output: terse summary + detailed tables."""
from typing import Dict, List


def render_summary(scores: Dict, regressions: List[Dict]) -> str:
    """One-line-per-app pass/fail summary."""
    lines = []
    if regressions:
        lines.append(f"\n[!] FAIL — {len(regressions)} regression(s) detected:\n")
        for r in regressions:
            lines.append(
                f"  {r['app']:>20s}  {r['detector']:>25s}  "
                f"{r['layer']:>10s}.{r['metric']:<10s}  "
                f"baseline={r['baseline']:.3f}  current={r['current']:.3f}  "
                f"delta={r['delta']:+.3f}"
            )
    else:
        lines.append("\n[+] PASS — no regressions detected\n")

    lines.append("\nSummary:")
    for app, app_scores in scores.items():
        if app_scores.get("error"):
            lines.append(f"  {app}: ERROR — {app_scores['error']}")
            continue
        detectors = ", ".join(sorted(app_scores.keys()))
        lines.append(f"  {app}: {len(app_scores)} detectors evaluated ({detectors})")

    return "\n".join(lines)


def render_detail_table(scores: Dict) -> str:
    """Full per-detector, per-layer breakdown table."""
    lines = [
        "",
        "=" * 100,
        f"{'App':<20s} {'Detector':<30s} {'Layer':<12s} {'Precision':>10s} {'Recall':>8s} {'F1':>8s}",
        "-" * 100,
    ]
    for app, app_scores in scores.items():
        if app_scores.get("error"):
            lines.append(f"{app:<20s} ERROR: {app_scores['error']}")
            continue
        for detector_name, layer_scores in sorted(app_scores.items()):
            for layer_name, metrics in sorted(layer_scores.items()):
                lines.append(
                    f"{app:<20s} {detector_name:<30s} {layer_name:<12s} "
                    f"{metrics['precision']:>10.3f} {metrics['recall']:>8.3f} {metrics['f1']:>8.3f}"
                )
    lines.append("=" * 100)
    return "\n".join(lines)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_report.py -v
```
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add bench/report.py tests/bench/test_report.py
git commit -m "bench: report rendering (summary + detail table)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 13: Wire CLI to runner + baseline + update modules

**Files:**
- Modify: `bench/cli.py`
- Create: `bench/update.py`, `tests/bench/test_cli.py`

- [ ] **Step 1: Write failing tests**

`tests/bench/test_cli.py`:
```python
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_cli_help():
    result = subprocess.run(
        ["python", "-m", "bench", "--help"],
        capture_output=True, text=True, cwd=REPO_ROOT, timeout=10,
    )
    assert result.returncode == 0
    assert "--apps" in result.stdout
    assert "--save-baseline" in result.stdout


def test_cli_apps_filter_unknown():
    """Unknown app filter doesn't crash, just runs nothing."""
    result = subprocess.run(
        ["python", "-m", "bench", "--apps", "nonexistent_app", "--layer", "a"],
        capture_output=True, text=True, cwd=REPO_ROOT, timeout=30,
    )
    assert result.returncode == 0  # No regressions because no apps ran
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_cli.py -v
```
Expected: `test_cli_help` may pass (placeholder); `test_cli_apps_filter_unknown` fails because the placeholder doesn't accept `--layer`.

- [ ] **Step 3: Create update module (skeleton)**

`bench/update.py`:
```python
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

        # Import the per-app extractor
        module_path = f"bench.corpus.{app.name}.extractor"
        extractor_mod = __import__(module_path, fromlist=["extract"])
        labels = extractor_mod.extract()

        # Serialize
        data = []
        for lab in labels:
            d = asdict(lab)
            d["location"] = d["location"].value
            d["vuln_types"] = [v.value for v in d["vuln_types"]]
            data.append(d)

        out_path = app.config_path.parent / "labels.json"
        out_path.write_text(json.dumps(data, indent=2))
        log.info(f"  wrote {len(data)} labels to {out_path}")
```

- [ ] **Step 4: Replace bench/cli.py with the real implementation**

`bench/cli.py`:
```python
"""CLI entry point for the detector accuracy harness."""
import argparse
import json
import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BENCH_ROOT = Path(__file__).resolve().parent
CORPUS_ROOT = BENCH_ROOT / "corpus"
BASELINE_PATH = BENCH_ROOT / "baseline.json"


def build_parser():
    p = argparse.ArgumentParser(
        prog="bench",
        description="Detector accuracy harness for sqli-recon. "
                    "Measures precision/recall against labeled corpus.",
    )
    p.add_argument("--detail", action="store_true",
                   help="Show full per-finding breakdown")
    p.add_argument("--apps", type=str, default=None,
                   help="Comma-separated subset of corpus apps")
    p.add_argument("--detectors", type=str, default=None,
                   help="Comma-separated detector substrings to filter")
    p.add_argument("--save-baseline", action="store_true",
                   help="Persist current scores as new baseline (overwrite baseline.json)")
    p.add_argument("--update-labels", action="store_true",
                   help="Refresh corpus labels from upstream and exit")
    p.add_argument("--layer", choices=["a", "b", "both"], default="both",
                   help="Run only Layer A (isolated), Layer B (end-to-end), or both")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    # --update-labels: refresh and exit
    if args.update_labels:
        from bench.update import update_all_labels
        update_all_labels(CORPUS_ROOT)
        print("[+] Labels updated.")
        return 0

    from bench.runner import run_all
    from bench.score import diff_vs_baseline
    from bench.report import render_summary, render_detail_table

    app_filter = args.apps.split(",") if args.apps else None
    detector_filter = args.detectors.split(",") if args.detectors else None

    # Run harness
    scores = run_all(
        corpus_root=CORPUS_ROOT,
        app_filter=app_filter,
        detector_filter=detector_filter,
        layer=args.layer,
        cwd=REPO_ROOT,
    )

    # Load baseline (if exists)
    if BASELINE_PATH.exists():
        baseline = json.loads(BASELINE_PATH.read_text())
        regressions = diff_vs_baseline(scores, baseline)
    else:
        # First run: create baseline, no regressions
        BASELINE_PATH.write_text(json.dumps(scores, indent=2))
        print(f"[*] No baseline found — created {BASELINE_PATH}")
        baseline = scores
        regressions = []

    # --save-baseline: overwrite
    if args.save_baseline:
        BASELINE_PATH.write_text(json.dumps(scores, indent=2))
        print(f"[+] Baseline saved to {BASELINE_PATH}")

    # Render output
    print(render_summary(scores, regressions))
    if args.detail:
        print(render_detail_table(scores))

    return 1 if regressions else 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/test_cli.py -v
```
Expected: 2 passed.

- [ ] **Step 6: Smoke-test the full CLI manually**

```bash
cd ~/projects/sqli-recon && python -m bench --help
cd ~/projects/sqli-recon && python -m bench --apps vulnerable_app --layer a
```
Expected: First creates `bench/baseline.json` and exits 0.

- [ ] **Step 7: Commit**

```bash
git add bench/cli.py bench/update.py tests/bench/test_cli.py
git commit -m "bench: real CLI dispatcher + baseline persistence + --update-labels

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 14: Final smoke test + bench/README usage examples

**Files:**
- Modify: `bench/README.md` (expand usage examples)
- Modify: `bench/baseline.json` (commit the initial baseline)

- [ ] **Step 1: Run the full default harness on vulnerable_app only**

```bash
cd ~/projects/sqli-recon && python -m bench --apps vulnerable_app
```
Expected: Creates baseline (first run), prints PASS, exits 0.

- [ ] **Step 2: Run again — should be PASS with baseline diff**

```bash
cd ~/projects/sqli-recon && python -m bench --apps vulnerable_app
```
Expected: PASS — no regressions.

- [ ] **Step 3: Run with --detail**

```bash
cd ~/projects/sqli-recon && python -m bench --apps vulnerable_app --detail
```
Expected: PASS + full per-detector breakdown table.

- [ ] **Step 4: (If docker available) Run DVWA**

```bash
cd ~/projects/sqli-recon && python -m bench --apps dvwa --layer a --detail
```
Expected: DVWA spins up in docker, runs Layer A, exits 0.

- [ ] **Step 5: Expand bench/README.md with example output**

Append to `bench/README.md`:
```markdown

## Example output

```
$ python -m bench --apps vulnerable_app

[+] PASS — no regressions detected

Summary:
  vulnerable_app: 3 detectors evaluated (CommandInjectionDetector, ErrorDetector, SSTIDetector)
```

## Adding a new corpus app

1. Create `bench/corpus/<name>/` directory
2. Add `app.yaml` matching the schema (see `bench/corpus/vulnerable_app/app.yaml`)
3. Add `extractor.py` exporting `extract() -> list[Label]`
4. Run `python -m bench --update-labels` to generate the initial `labels.json`
5. Commit all four files
```

- [ ] **Step 6: Commit baseline + README**

```bash
git add bench/baseline.json bench/README.md
git commit -m "bench: initial baseline + README examples

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 7: Run the full bench test suite**

```bash
cd ~/projects/sqli-recon && pytest tests/bench/ -v
```
Expected: All non-integration tests pass. Integration tests pass if vulnerable_app / docker available.

- [ ] **Step 8: Verify end-user install still works (no regression)**

```bash
cd ~/projects/sqli-recon && grep -A 5 "^\[project\.optional-dependencies\]" pyproject.toml
```
Expected: `bench = [...]` is present but does NOT appear in core `dependencies`. End-user `./setup.sh` is untouched.

---

## Out of scope for this plan (reminder)

- `.claude/agents/detector-accuracy-harness.md` subagent wrapper — Phase 2
- `bench/sqlmap_oracle.py` sqlmap comparison — Phase 3
- CI workflow / Claude Code hook — Phase 4
- Juice Shop / WebGoat corpus apps — future additive work

When Phase 1 lands and the harness has been used a few times, the maintainer will pick which Phase to tackle next.
