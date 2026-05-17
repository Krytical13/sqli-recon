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
    Run a minimal in-process scan against base_url. Returns the list of Findings.

    Implementation note: this reproduces the essential pipeline from
    sqli_recon/cli.py (crawl -> JS analyze -> classify -> run detectors) rather
    than invoking cli.main() directly. cli.main() does many side-effects
    (file writes, sys.exit) that make it unsuitable as a library call.
    """
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
