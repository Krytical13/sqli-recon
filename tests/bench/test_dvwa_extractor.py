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
    assert any(lab.url_path == "/vulnerabilities/sqli/" and lab.parameter == "id"
               for lab in sqli)


def test_extract_finds_cmdi():
    labels = extract()
    cmdi = [lab for lab in labels if VulnType.CMDI in lab.vuln_types]
    assert len(cmdi) >= 1
