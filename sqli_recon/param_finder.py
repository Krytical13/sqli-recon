"""Hidden parameter discovery via response differential analysis."""

import hashlib
import time
import logging
from urllib.parse import urlparse, urlencode

from sqli_recon.models import Endpoint, Parameter, ParamLocation, Source
from sqli_recon.wordlists import SQLI_HIGH_RISK_PARAMS, SQLI_MEDIUM_RISK_PARAMS, ALL_PARAMS

log = logging.getLogger(__name__)

SENTINEL = "sqr3c0n"


class ParamFinder:
    """
    Discovers hidden parameters on endpoints by comparing response differentials.

    Optimized for Tor/slow connections:
    - Prioritizes endpoints with few/no visible params (highest value)
    - Uses only high+medium risk param names by default (not the full 291)
    - Larger batches = fewer requests
    - Per-endpoint timeout prevents stalling
    - Total time budget prevents runaway scans
    - Graceful connection failure handling (skip, don't retry)
    """

    def __init__(self, client, wordlist=None, batch_size=50, max_time=300):
        self.client = client
        # Default: only fuzz SQL-relevant params, not everything
        self.wordlist = wordlist or (SQLI_HIGH_RISK_PARAMS + SQLI_MEDIUM_RISK_PARAMS)
        self.batch_size = batch_size
        self.max_time = max_time  # Total seconds budget for all fuzzing
        self._errors = 0
        self._max_errors = 10  # Abort after this many connection failures

    def discover(self, endpoints, progress_callback=None):
        """
        Test endpoints for hidden parameters.
        Prioritizes endpoints with fewest known params (highest discovery value).
        """
        results = []
        start_time = time.time()

        # Sort: endpoints with 0 params first (most likely to discover new ones),
        # then by fewest params. Skip endpoints with 5+ params (already well-mapped).
        prioritized = sorted(
            [ep for ep in endpoints if len(ep.parameters) < 5],
            key=lambda ep: len(ep.parameters),
        )

        # Deduplicate by base_url + method (don't fuzz the same endpoint twice)
        seen = set()
        unique = []
        for ep in prioritized:
            key = (ep.base_url, ep.method)
            if key not in seen:
                seen.add(key)
                unique.append(ep)

        total = len(unique)

        for i, endpoint in enumerate(unique):
            # Time budget check
            elapsed = time.time() - start_time
            if elapsed > self.max_time:
                log.info(f"Fuzz time budget exhausted ({self.max_time}s), stopping")
                if progress_callback:
                    progress_callback(i, total)
                break

            # Error budget check
            if self._errors >= self._max_errors:
                log.warning(f"Too many connection failures ({self._errors}), stopping fuzzer")
                break

            if progress_callback and (i + 1) % 2 == 0:
                progress_callback(i + 1, total)

            found = self._fuzz_endpoint(endpoint)
            if found:
                results.append(found)

        if progress_callback:
            progress_callback(min(i + 1, total), total)

        return results

    def _fuzz_endpoint(self, endpoint):
        """Fuzz a single endpoint for hidden parameters."""
        url = endpoint.base_url
        method = endpoint.method

        # Get baseline response
        baseline = self._get_baseline(url, method)
        if baseline is None:
            self._errors += 1
            return None

        known_params = {p.name for p in endpoint.parameters}
        candidates = [p for p in self.wordlist if p not in known_params]
        if not candidates:
            return None

        discovered = []
        for batch_start in range(0, len(candidates), self.batch_size):
            batch = candidates[batch_start:batch_start + self.batch_size]
            found = self._test_batch(url, method, batch, baseline, max_depth=2)
            discovered.extend(found)

        if not discovered:
            return None

        new_params = list(endpoint.parameters)
        for param_name in discovered:
            new_params.append(Parameter(
                name=param_name,
                location=ParamLocation.QUERY if method == "GET" else ParamLocation.BODY,
                value="",
                param_type="string",
            ))

        return Endpoint(
            url=endpoint.url,
            method=method,
            parameters=new_params,
            content_type=endpoint.content_type,
            source=Source.FUZZ,
            status_code=endpoint.status_code,
            response_headers=endpoint.response_headers,
        )

    def _get_baseline(self, url, method):
        if method == "GET":
            resp = self.client.get(url)
        else:
            resp = self.client.post(url)
        if resp is None:
            return None
        return ResponseSignature(resp)

    def _test_batch(self, url, method, param_names, baseline, max_depth=3):
        """Test a batch with limited recursion depth to prevent runaway requests."""
        params = {name: f"{SENTINEL}{i}" for i, name in enumerate(param_names)}

        if method == "GET":
            resp = self.client.get(url, params=params)
        else:
            resp = self.client.post(url, data=params)

        if resp is None:
            self._errors += 1
            return []

        sig = ResponseSignature(resp)

        if sig.is_similar(baseline):
            return []

        if len(param_names) == 1:
            return param_names

        # Limit binary search depth to prevent exponential requests over Tor
        if max_depth <= 0:
            # Can't narrow further — return the whole batch as "contains valid params"
            # Better to over-report than burn 50 more requests over Tor
            return param_names

        mid = len(param_names) // 2
        left = self._test_batch(url, method, param_names[:mid], baseline, max_depth - 1)
        right = self._test_batch(url, method, param_names[mid:], baseline, max_depth - 1)
        return left + right

    def discover_methods(self, endpoints, progress_callback=None):
        """Test which HTTP methods each endpoint accepts."""
        methods_to_test = ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        results = []

        # Deduplicate
        seen = set()
        unique = []
        for ep in endpoints:
            if ep.base_url not in seen:
                seen.add(ep.base_url)
                unique.append(ep)

        for i, endpoint in enumerate(unique):
            if progress_callback and (i + 1) % 5 == 0:
                progress_callback(i + 1, len(unique))

            for method in methods_to_test:
                if method == endpoint.method:
                    continue
                resp = self.client.request(method, endpoint.base_url)
                if resp is not None and resp.status_code not in (404, 405, 501):
                    results.append(Endpoint(
                        url=endpoint.url,
                        method=method,
                        parameters=list(endpoint.parameters),
                        source=Source.FUZZ,
                        status_code=resp.status_code,
                        response_headers=dict(resp.headers),
                    ))

        return results


class ResponseSignature:
    """Captures key response characteristics for comparison."""

    def __init__(self, response):
        self.status_code = response.status_code
        self.content_length = len(response.content)
        self.content_hash = hashlib.md5(response.content).hexdigest()
        text = response.text
        self.line_count = text.count("\n")
        self.word_count = len(text.split())
        self.content_type = response.headers.get("Content-Type", "")

    def is_similar(self, other, length_threshold=0.05):
        if self.status_code != other.status_code:
            return False
        if self.content_hash == other.content_hash:
            return True
        if other.content_length > 0:
            length_ratio = abs(self.content_length - other.content_length) / other.content_length
            if length_ratio > length_threshold:
                return False
        if other.line_count > 0:
            line_ratio = abs(self.line_count - other.line_count) / max(other.line_count, 1)
            if line_ratio > 0.02:
                return False
        return True
