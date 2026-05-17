# sqli-recon Review TODO (2026-05-17)

Findings from code review at commit `b927219`. Items grouped by priority and cited to `file:line`.

---

## P0 — Real bugs

### 1. CAPTCHA solver always captures cookies after 2s
**File**: `sqli_recon/captcha_solver.py:115`
```python
if solved or time.time() - start >= 2:
```
Condition is true on second iteration regardless of solve state. Should be `if solved:`.

### 2. Response-analysis loop wastes requests when no DB-like response found
**File**: `sqli_recon/cli.py:600-611`
The `if len(db_like_urls) >= 5: break` only triggers on *found* count, so a target with zero DB-like responses gets one extra GET per endpoint (200+ wasted requests on a full scan, painful over Tor). Track a separate `checked` counter and break on `checked >= 10`.

### 3. SSTI `{{7*7}}` matches literal "49" anywhere in response
**File**: `sqli_recon/intelligence.py:171`
Any page with "49" in it (timestamps, IDs, prices) triggers a confirmed SSTI finding. Need to baseline first — verify "49" wasn't in the response when sent a normal value — and prefer rarer markers like `{{91*97}}=8827`.

### 4. CmdI time-based detector with single baseline sample
**File**: `sqli_recon/intelligence.py:241-253`
One baseline + 4s threshold is unreliable over Tor or against cold-cache backends. Take 3 baseline samples, use `median + 2*stdev + 4` as threshold. Also cap to top-N most-likely params — `sleep 5` × 5 payloads × 50 medium findings = ~4 min of held connections (soft DoS).

### 5. Auth success when new cookies count > old
**File**: `sqli_recon/auth.py:240-242`
Failed-login pages rotate CSRF tokens and set analytics cookies. Heuristic marks failed logins as successful. Require an auth-shaped cookie name (`sessionid`, `PHPSESSID`, `JSESSIONID`, etc.) among the new ones.

### 6. Threading defeats Tor rate limit
**Files**: `sqli_recon/intelligence.py:113` (ErrorDetector `max_workers=3`), `sqli_recon/cli.py:505` (API brute `max_workers=5`)
`_rate_limit_wait` has a single `_last_request_time` and no lock — under Tor, 3-5 concurrent requests fire near-simultaneously and the circuit drops. Either pass `max_workers=1` when `tor_mode`, or guard rate-limit with `threading.Lock`.

### 7. JSON report emits misleading `sqlmap_url` for body/JSON params
**File**: `sqli_recon/output.py:224`
`_build_marked_url` returns base_url with no marker for body/JSON params (line 152-153). The URL list correctly filters them out, but the JSON report still emits the value — implies the marker is present when it isn't.

### 8. Dead diff calculation
**File**: `sqli_recon/cli.py:550-551`
`Endpoint.__eq__` compares param sets. Fuzz results have *more* params than originals by definition, so `e in fuzz_results` is always False and the subtraction is always 0. Delete or fix.

### 9. Content-Length uses string length, not byte length
**File**: `sqli_recon/models.py:164`
`f"Content-Length: {len(body)}"` — breaks sqlmap parsing for any multibyte content. Use `len(body.encode('utf-8'))`.

### 10. Phase numbering broken in CLI
**File**: `sqli_recon/cli.py`
`# Phase 7: Response Analysis` (line 597) and `# Phase 7: Output` (line 747) are both Phase 7. Phase 5b/9b/9c sub-numbering implies a fix was meant. Renumber to a clean sequence.

### 11. CmdI/SSTI false-positive on reflected XSS endpoints
**Files**: `sqli_recon/intelligence.py:194-199` (CMDI_PROBES), `:133-143` (SSTI_PROBES)
If a param's value is echoed back unchanged (reflected XSS, search box echo), the unique marker appears in the response and triggers a "confirmed" CmdI/SSTI. Need to verify the marker appears in a context that proves execution — e.g., for CmdI require both `; echo X` AND `echo X` to be present without the semicolon. Or run a "control" with the marker quoted to see if the marker alone reflects.

---

## P1 — Architecture / accuracy

### 12. `--quick` doesn't match its docs
**File**: `sqli_recon/cli.py:166-176`
Docs say "Fast scan: crawl + JS analysis only" but only fuzz/api-brute/method-fuzz are disabled. Header injection, GraphQL, ResponseAnalyzer, ErrorDetector, SSTIDetector, CommandInjectionDetector all still run. Either gate the intelligence block under `not args.quick` or update help text.

### 13. `cli.py` is 895 lines of mixed orchestration + presentation
- `if not args.quiet and not args.json_only:` appears ~30 times
- Phase logic mixed with side-effecting print/logging
- `gather.py` duplicates ~half of `cli.py`'s network/auth/output setup
**Suggestion**: extract `Reporter` class owning verbosity state, split each phase into `run_<phase>(state, args)` returning new state. Shared setup goes in `setup.py` helper that both CLIs call.

### 14. `intelligence.py` is 1039 lines with 8 classes
Split into `intelligence/` package — one file per detector (`error_detector.py`, `ssti_detector.py`, `cmdi_detector.py`, `headers.py`, `tech.py`, `response.py`, `graphql.py`, `second_order.py`).

### 15. `Endpoint.response_headers["_db_like"]` smuggles state through HTTP headers
**Files**: `sqli_recon/cli.py:608` → `sqli_recon/classifier.py:130`
Mutates the dict that's supposed to be HTTP response headers. Add explicit `notes: dict = field(default_factory=dict)` on Endpoint.

### 16. `sqlmap_urls.txt` loses auth context
**File**: `sqli_recon/output.py:95-115`
README implies `sqlmap -m sqlmap_urls.txt` works, but cookie/UA only get baked into `requests/` files. Emit a `sqlmap_urls_cmd.sh` wrapper with `--cookie` / `--user-agent` flags.

### 17. Crawler surface dedup may skip pagination
**File**: `sqli_recon/crawler.py:165-168`
`?tid=1&page=2` and `?tid=1&page=3` dedupe to the first one — deep forum threads stop at page 1. Either crawl 2-3 unique value combinations per surface, or special-case pagination params.

### 18. No CI workflow
`tests/test_suite.py` is healthy (unit + integration markers) but doesn't run on PR. Add `.github/workflows/test.yml` running `pytest -v -m "not integration"`.

### 19. Bare `except Exception: pass` everywhere
**Files**: `intelligence.py:295-296`, `crawler.py:147-149`, `captcha_solver.py` multiple
Silently swallow real bugs. At minimum log to debug; better, catch specific exceptions.

---

## P2 — Small / polish

### 20. `requirements.txt` has both `requests` and `requests[socks]`
Second supersedes first; drop line 1.

### 21. Backwards-compat flags are dead code
**File**: `sqli_recon/cli.py:94-95`
`--fuzz`, `--brute-api` are SUPPRESS'd in argparse but never read. Only `skip_js` is checked. Delete or wire up.

### 22. Hardcoded `5` for CAPTCHA streak in two places
**Files**: `crawler.py:115`, `cli.py:418`
Centralize as `CAPTCHA_ABORT_THRESHOLD`.

### 23. Headless crawler doesn't feed `TechFingerprint`
`HeadlessCrawler` captures rich responses but doesn't pass them to the fingerprinter. Same for `_collect_response_samples` in `gather.py`. Adding these would meaningfully improve tech detection on SPAs.

### 24. Path-param marker replacement is positional
**File**: `sqli_recon/output.py:144-145`
`path.replace(param.value, param.value + "*", 1)` — if value appears multiple times in path (`/users/123/posts/123`), marks the wrong one. The crawler's `_detect_path_params` already computes spans (`crawler.py:270`); pass through.

### 25. No sanitizer round-trip test
`sqli_recon/sanitizer.py` is complex bidirectional logic with no test asserting `desanitize(sanitize_text(x)) == x` for various inputs.

### 26. Generic deserialization match has FP risk
**File**: `sqli_recon/passive.py:103`
`Large Base64 Blob` (≥200 chars in `value|cookie|token=...`) hits on legitimate signed cookies, JWTs already detected separately. Already `medium` severity — fine, but document the FP rate.

### 27. CAPTCHA detection threshold may miss heavy challenge pages
**File**: `sqli_recon/http_client.py:286-287`
Single-marker hit only triggers if body < 3000 chars. Real CAPTCHA pages with full CSS/JS often exceed that.

