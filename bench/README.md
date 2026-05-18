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

## Example output

```
$ python3 -m bench --apps vulnerable_app

[+] PASS — no regressions detected

Summary:
  vulnerable_app: 4 detectors evaluated (CommandInjectionDetector, ErrorDetector, HeaderInjectionScanner, SSTIDetector)
```

For full breakdown:

```
$ python3 -m bench --apps vulnerable_app --detail

[+] PASS — no regressions detected

Summary:
  vulnerable_app: 4 detectors evaluated (CommandInjectionDetector, ErrorDetector, HeaderInjectionScanner, SSTIDetector)

====================================================================================================
App                  Detector                       Layer         Precision   Recall       F1
----------------------------------------------------------------------------------------------------
vulnerable_app       CommandInjectionDetector       end_to_end        0.000    0.000    0.000
vulnerable_app       CommandInjectionDetector       isolated          0.000    0.000    0.000
vulnerable_app       ErrorDetector                  end_to_end        1.000    0.148    0.258
vulnerable_app       ErrorDetector                  isolated          1.000    0.111    0.200
vulnerable_app       HeaderInjectionScanner         end_to_end        1.000    0.148    0.258
vulnerable_app       SSTIDetector                   end_to_end        0.000    0.000    0.000
vulnerable_app       SSTIDetector                   isolated          0.000    0.000    0.000
====================================================================================================
```

Shows precision/recall/F1 per detector per layer (isolated + end_to_end).

## Adding a new corpus app

1. Create `bench/corpus/<name>/` directory
2. Add `app.yaml` matching the schema (see `bench/corpus/vulnerable_app/app.yaml`)
3. Add `extractor.py` exporting `extract() -> list[Label]`
4. Run `python3 -m bench --update-labels` to generate the initial `labels.json`
5. Commit all four files

## Known limitations (Phase 1)

- **DVWA `ErrorDetector` recall is 0**: the `vulnerables/web-dvwa:latest` image runs PHP with `display_errors=Off`, suppressing SQL syntax errors. Layer A correctness verified against vulnerable_app where errors are visible. Phase 2 may add a custom DVWA image with `display_errors=On`.
- **First-run latency**: a full bench run takes ~6 minutes per app (Layer B does a full crawl + classify + probe). Iterate with `--layer a` for fast feedback.
- **`/login` GET phantom label**: the vulnerable_app's /login route is annotated SQLi for both GET and POST, but the SQL only fires on POST. Causes one expected FN. Annotation syntax may grow method-specific support later.
