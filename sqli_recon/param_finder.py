"""Hidden parameter discovery via response differential analysis."""

import hashlib
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlencode, urljoin

from sqli_recon.models import Endpoint, Parameter, ParamLocation, Source
from sqli_recon.wordlists import ALL_PARAMS

log = logging.getLogger(__name__)

# Unique sentinel values for each parameter to detect reflections
SENTINEL = "sqr3c0n"


class ParamFinder:
    """
    Discovers hidden parameters on endpoints by comparing response differentials.

    Approach:
    1. Get baseline response for the endpoint
    2. Send batches of candidate parameters with unique sentinel values
    3. If response differs from baseline, binary search the batch to find which params are valid
    """

    def __init__(self, client, wordlist=None, batch_size=40, threads=5):
        self.client = client
        self.wordlist = wordlist or ALL_PARAMS
        self.batch_size = batch_size
        self.threads = threads

    def discover(self, endpoints, progress_callback=None):
        """
        Test a list of endpoints for hidden parameters.
        Returns list of new Endpoints with discovered parameters.
        """
        results = []
        total = len(endpoints)

        for i, endpoint in enumerate(endpoints):
            if progress_callback and (i + 1) % 2 == 0:
                progress_callback(i + 1, total)

            # Only fuzz endpoints that seem worth it (have a base URL that responds)
            found = self._fuzz_endpoint(endpoint)
            if found:
                results.append(found)

        if progress_callback:
            progress_callback(total, total)

        return results

    def _fuzz_endpoint(self, endpoint):
        """Fuzz a single endpoint for hidden parameters."""
        url = endpoint.base_url
        method = endpoint.method

        # Get baseline response
        baseline = self._get_baseline(url, method)
        if baseline is None:
            return None

        # Already-known param names - skip these
        known_params = {p.name for p in endpoint.parameters}

        # Filter wordlist to exclude known params
        candidates = [p for p in self.wordlist if p not in known_params]
        if not candidates:
            return None

        # Test in batches
        discovered = []
        for batch_start in range(0, len(candidates), self.batch_size):
            batch = candidates[batch_start:batch_start + self.batch_size]
            found = self._test_batch(url, method, batch, baseline)
            discovered.extend(found)

        if not discovered:
            return None

        # Create new endpoint with discovered params
        new_params = list(endpoint.parameters)  # Keep existing params
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
        """Get baseline response signature."""
        if method == "GET":
            resp = self.client.get(url)
        else:
            resp = self.client.post(url)

        if resp is None:
            return None

        return ResponseSignature(resp)

    def _test_batch(self, url, method, param_names, baseline):
        """Test a batch of parameters. Returns list of valid param names."""
        # Build request with all params in the batch
        params = {name: f"{SENTINEL}{i}" for i, name in enumerate(param_names)}

        if method == "GET":
            resp = self.client.get(url, params=params)
        else:
            resp = self.client.post(url, data=params)

        if resp is None:
            return []

        sig = ResponseSignature(resp)

        if sig.is_similar(baseline):
            # No change - none of these params are valid
            return []

        if len(param_names) == 1:
            return param_names

        # Batch caused a change - binary search
        mid = len(param_names) // 2
        left = self._test_batch(url, method, param_names[:mid], baseline)
        right = self._test_batch(url, method, param_names[mid:], baseline)
        return left + right

    def discover_methods(self, endpoints, progress_callback=None):
        """
        Test which HTTP methods each endpoint accepts.
        Useful for finding POST/PUT/DELETE on endpoints only seen via GET.
        """
        methods_to_test = ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        results = []

        for i, endpoint in enumerate(endpoints):
            if progress_callback and (i + 1) % 5 == 0:
                progress_callback(i + 1, len(endpoints))

            url = endpoint.base_url
            for method in methods_to_test:
                if method == endpoint.method:
                    continue
                resp = self.client.request(method, url)
                if resp is not None and resp.status_code not in (404, 405, 501):
                    new_ep = Endpoint(
                        url=endpoint.url,
                        method=method,
                        parameters=list(endpoint.parameters),
                        source=Source.FUZZ,
                        status_code=resp.status_code,
                        response_headers=dict(resp.headers),
                    )
                    results.append(new_ep)

        return results


class ResponseSignature:
    """Captures key response characteristics for comparison."""

    def __init__(self, response):
        self.status_code = response.status_code
        self.content_length = len(response.content)
        self.content_hash = hashlib.md5(response.content).hexdigest()
        # Count of key structural elements (rough similarity)
        text = response.text
        self.line_count = text.count("\n")
        self.word_count = len(text.split())
        # Headers that might change
        self.content_type = response.headers.get("Content-Type", "")

    def is_similar(self, other, length_threshold=0.05):
        """
        Check if two responses are similar enough to consider identical.
        Uses multiple signals to reduce false positives.
        """
        if self.status_code != other.status_code:
            return False

        if self.content_hash == other.content_hash:
            return True

        # Allow small length variations (dynamic content like timestamps, CSRF tokens)
        if other.content_length > 0:
            length_ratio = abs(self.content_length - other.content_length) / other.content_length
            if length_ratio > length_threshold:
                return False

        # Line/word count should be very close
        if other.line_count > 0:
            line_ratio = abs(self.line_count - other.line_count) / max(other.line_count, 1)
            if line_ratio > 0.02:
                return False

        return True
