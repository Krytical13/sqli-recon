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
