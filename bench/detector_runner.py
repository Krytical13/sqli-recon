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
    url = urljoin(base_url + "/", label.url_path.lstrip("/"))
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
        key_set = set()
        for finding, _detail in confirmed_pairs:
            for lab in labels:
                lab_url = urljoin(base_url + "/", lab.url_path.lstrip("/"))
                if finding.endpoint.url.startswith(lab_url) and \
                   finding.parameter.name == (lab.parameter or "_"):
                    key_set.add((lab.url_path, lab.method, lab.parameter))
                    break
        found[detector_name] = key_set

    return found
