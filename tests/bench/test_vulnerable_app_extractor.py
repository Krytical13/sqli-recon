from pathlib import Path

from bench.corpus.vulnerable_app.extractor import extract
from sqli_recon.models import ParamLocation, VulnType


def test_extract_finds_annotated_vuln():
    labels = extract()
    assert len(labels) > 0
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
