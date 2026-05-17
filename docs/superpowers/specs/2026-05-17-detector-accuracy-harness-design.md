# Detector Accuracy Harness — Design

**Date**: 2026-05-17
**Status**: Approved, ready for implementation planning
**Audience**: sqli-recon maintainers and contributors (NOT end users)

---

## 1. Motivation

sqli-recon's value lives in the accuracy of its detectors (`ErrorDetector`, `SSTIDetector`, `CommandInjectionDetector`, `HeaderInjectionScanner`). Today there is no objective measure of "did this change improve or regress accuracy?" — the only signal is integration tests against `tests/vulnerable_app.py` that assert minimum recall, not precision/recall trajectories over time.

This harness gives the maintainer (and any contributor) a measurable, repeatable answer to: *did my detector change make things better or worse?*

## 2. Goals

- Measure precision/recall/F1 per detector against a known-labeled corpus
- Detect regressions automatically (any metric drop > threshold → fail)
- Compare current run against a persisted baseline; show clear diff
- Cover both isolated detector behavior AND end-to-end pipeline behavior
- Extensible: adding a new corpus app = one new directory, no core changes
- Set-and-forget: default invocation gives pass/fail; verbose mode for investigation
- Eventually benchmark against sqlmap as an independent oracle (Phase 3)

## 3. Non-goals

- Not a fuzzer — corpus is known/labeled, not random
- Not a user-facing feature — `./setup.sh` and `./scan` stay untouched for end users
- Not a replacement for unit tests — pytest still owns code-correctness assertions
- Not a CVE scanner — harness measures detector accuracy, not real-world vulnerability discovery

## 4. Audience and install isolation

The harness is **developer infrastructure**, analogous to a Rust crate's `benches/` or a Python library's `tests/`:

- End users `git clone && ./setup.sh && ./scan` — never touch `bench/`, no docker required, install footprint unchanged
- Maintainers/contributors run `cd bench && ./setup.sh` (or `pip install -e '.[bench]'`) once to enable harness deps (docker, image pulls, etc.)
- CI (Phase 4, optional) runs the harness on PR

## 5. Architecture

```
sqli-recon/
├── sqli_recon/         (existing — tool itself, unchanged)
├── tests/              (existing — pytest, unchanged)
└── bench/              (NEW — the harness)
    ├── corpus/
    │   ├── vulnerable_app/
    │   │   ├── app.yaml
    │   │   ├── extractor.py
    │   │   └── labels.json     (committed)
    │   └── dvwa/
    │       ├── app.yaml
    │       ├── extractor.py
    │       └── labels.json     (committed)
    ├── runner.py
    ├── baseline.json           (committed)
    ├── update.py
    ├── cli.py
    ├── config.toml             (regression thresholds, etc.)
    └── setup.sh                (one-time dev install)
```

Plus three thin wrappers built in later phases:
- `.claude/agents/detector-accuracy-harness.md` — Claude subagent (Phase 2)
- `.github/workflows/bench.yml` — CI on PR (Phase 4 option A)
- Claude Code `PostToolUse` hook on detector edits (Phase 4 option B)

## 6. Components

### 6.1 `bench/corpus/<app>/` — per-app pluggable adapter

Each corpus app is a self-contained directory implementing the same interface:

- `app.yaml` — declarative app metadata: docker image (or process command), port, healthcheck URL, healthcheck timeout, optional setup commands (e.g., DVWA's "Create / Reset Database")
- `extractor.py` — exports a single `extract() -> list[Label]` function that converts the app's native metadata into normalized labels
- `labels.json` — generated cache; committed so the harness works offline and label changes are visible in PR diffs

Adding a new corpus app = one new directory matching this layout. No changes to `runner.py` or `cli.py`.

### 6.2 Normalized `Label` schema (the contract)

```python
@dataclass
class Label:
    app: str                       # "dvwa", "vulnerable_app"
    url_path: str                  # "/vulnerabilities/sqli/"
    method: str                    # "GET"
    parameter: str                 # "id"
    location: ParamLocation        # QUERY / BODY / JSON / PATH / HEADER
    vuln_types: list[VulnType]     # [SQLI], [SQLI, XSS], etc.
    context: dict                  # app-specific: {"security_level": "low"} for DVWA
```

Reuses sqli-recon's existing `ParamLocation` and `VulnType` enums from `sqli_recon/models.py` — no parallel taxonomy.

### 6.3 `bench/runner.py` — orchestration

Pure-function pipeline, each step independently testable:

```
setup_app(name)               → app handle (URL, cleanup callback)
load_labels(name)             → list[Label]
run_detectors(target_url)     → list[Finding]   # Layer A — synthetic, per-detector
run_full_scan(target_url)     → list[Finding]   # Layer B — end-to-end
compare(findings, labels)     → dict[detector_name, {tp, fp, fn}]
score(comparison)             → dict[detector_name, {precision, recall, f1}]
diff_vs_baseline(scores)      → list[Regression]   # empty = pass
teardown_app(handle)
```

**Key design choice — two-layer measurement:**

- **Layer A (isolated)**: build synthetic `Finding` objects from labels, invoke each detector class directly (`ErrorDetector(client).test_findings(...)`). Fast, deterministic, isolates per-detector accuracy.
- **Layer B (end-to-end)**: invoke `sqli_recon.cli.main` on the corpus app URL, collect resulting `Finding`s. Catches integration regressions (classifier scoring below threshold, crawler missing endpoints) that Layer A would miss.

When the two layers diverge, the gap tells the maintainer whether a regression is in the detector itself or somewhere upstream in the pipeline.

### 6.4 `bench/baseline.json` — persisted prior scores

```json
{
  "vulnerable_app": {
    "ErrorDetector":  {"isolated": {"precision": 1.0, "recall": 0.85, "f1": 0.92},
                       "end_to_end": {"precision": 1.0, "recall": 0.80, "f1": 0.89}},
    "SSTIDetector":   {"isolated": {"precision": 0.90, "recall": 0.75, "f1": 0.82},
                       "end_to_end": {"precision": 0.85, "recall": 0.70, "f1": 0.77}}
  },
  "dvwa": {
    "ErrorDetector":  {"isolated": {...}, "end_to_end": {...}}
  }
}
```

Default regression rule: any metric drop > 0.05 fails. Threshold configurable in `bench/config.toml`. Updated via `--save-baseline` flag after an intentional, accepted change.

### 6.5 `bench/cli.py` — entry point

```bash
python -m bench                   # run all, exit 0 = pass, exit 1 = regression
python -m bench --detail          # full per-finding breakdown table
python -m bench --apps dvwa       # subset corpus
python -m bench --detectors error # subset detectors
python -m bench --save-baseline   # persist current as new baseline
python -m bench --update-labels   # refresh corpus labels (pull DVWA, re-extract)
python -m bench --layer a         # only run isolated layer (skip end-to-end)
```

### 6.6 `bench/update.py` — label refresh

Periodic maintenance: pulls fresh DVWA docker image, re-runs each extractor, writes new `labels.json` files. Reports any label deltas. Intended to be run by maintainer on-demand (not auto), or by CI on a weekly cron (Phase 4 option).

## 7. Data flow (one bench run)

```
$ python -m bench

[1] Discover corpus apps          → bench/corpus/*/app.yaml
[2] For each app:
    a. setup → start container/process, wait for healthcheck (60s timeout)
    b. load labels from bench/corpus/<app>/labels.json
    c. Layer A: build synthetic Findings, invoke each Detector class
    d. Layer B: invoke sqli_recon.cli.main on app URL, collect Findings
    e. compare both layers vs labels → per-detector precision/recall/f1
    f. teardown → kill container/process (guaranteed via context manager)
[3] Aggregate scores across all apps
[4] Diff vs bench/baseline.json
[5] Render report (default: pass/fail summary; --detail: full table)
[6] Exit 0 if no regressions, 1 otherwise
```

## 8. Error handling

Three failure classes, handled differently:

| Failure | Handling |
|---------|----------|
| Container won't start (port in use, docker missing, image pull fail) | Skip that app, mark as `ERROR`, continue with other apps, exit nonzero at end |
| Detector throws exception during a run | Capture, log to `bench/last_run.log`, mark detector as `ERROR` for that app, continue |
| Label extractor produces malformed output | Hard fail before any tests run — bug in extractor must be fixed before proceeding |
| `baseline.json` missing | First run: treat current scores as the baseline, write it, exit 0 with note "no baseline — created" |
| Ctrl+C during run | Context managers guarantee container teardown, partial results written to `bench/last_run.log` |

## 9. Phasing

| Phase | Scope | Deliverable |
|-------|-------|-------------|
| **1** | `bench/` engine + vulnerable_app + DVWA + Layer A + Layer B + CLI + baseline diff | `python -m bench` works, catches regressions on existing detectors |
| **2** | `.claude/agents/detector-accuracy-harness.md` subagent wrapper | Claude auto-invokes harness when editing detectors, reports back concisely |
| **3** | `bench/sqlmap_oracle.py` — sqlmap as independent oracle | Compares sqli-recon findings to sqlmap's findings on same corpus, reports agreement metrics |
| **4** (optional) | CI workflow OR Claude Code hook (pick after Phase 2 usage informs which is more useful) | Auto-runs harness on PR open / on detector edit |

Phase 1 is the foundation — Phases 2-4 build on it and produce no value without it. Phases 2-4 can ship in any order or be skipped entirely.

## 10. Open questions / future work

- **Juice Shop integration** (deferred from Phase 1): use `/api/Challenges` self-reporting trick to auto-derive labels by firing actual exploits and checking which challenges Juice Shop marks as solved. Elegant but requires sqli-recon to send real attacks during benchmarking, not just probes.
- **WebGoat, bWAPP, Hackazon**: each is a Phase-2+ corpus addition following the same extractor pattern.
- **Score thresholds**: regression threshold of 0.05 is a starting guess. Tune after seeing real-world variance across runs.
- **Stochastic detector runs**: some detectors (e.g., time-based CmdI) have inherent variance. Future work: run each detector N times, report median + stddev.
- **CI cost**: if CI is added in Phase 4, DVWA image pulls + container startup may push CI runtime past acceptable thresholds. Mitigation: cache docker images in CI runner.

## 11. References

- Existing test infrastructure: `tests/vulnerable_app.py`, `tests/test_suite.py`
- Detector implementations: `sqli_recon/intelligence.py` (1039 lines, 8 classes — see `REVIEW_TODO.md` #14 for proposed split)
- Models reused: `sqli_recon/models.py` (`ParamLocation`, `VulnType`, `Finding`)
- Related review findings: `REVIEW_TODO.md` items #3 (SSTI `{{7*7}}` literal-49 false positive), #4 (CmdI single-baseline jitter), and #11 (CmdI/SSTI false positives on reflected-XSS endpoints) are detector-accuracy bugs the harness will help validate fixes for
- DVWA: https://github.com/digininja/DVWA
- OWASP Juice Shop challenges API: https://github.com/juice-shop/juice-shop (see `data/static/challenges.yml`)
