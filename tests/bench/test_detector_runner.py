from unittest.mock import MagicMock

from bench.detector_runner import build_synthetic_finding, run_layer_a
from bench.label import Label
from sqli_recon.models import ParamLocation, VulnType


def _label(path, param, location, vt):
    return Label(app="x", url_path=path, method="GET", parameter=param,
                 location=location, vuln_types=[vt] if vt else [], context={})


def test_build_synthetic_finding_query():
    lab = _label("/users", "id", ParamLocation.QUERY, VulnType.SQLI)
    f = build_synthetic_finding(lab, base_url="http://x:8080")
    assert f.endpoint.url.startswith("http://x:8080/users")
    assert f.parameter.name == "id"
    assert f.score == 1.0


def test_build_synthetic_finding_body():
    lab = _label("/login", "password", ParamLocation.BODY, VulnType.SQLI)
    f = build_synthetic_finding(lab, base_url="http://x:8080")
    assert f.parameter.location == ParamLocation.BODY


def test_run_layer_a_reports_per_detector(monkeypatch):
    """Layer A invokes each detector on each label, returns per-detector found-set."""
    labels = [_label("/users", "id", ParamLocation.QUERY, VulnType.SQLI)]

    fake_finding = MagicMock()
    fake_finding.endpoint.url = "http://x:8080/users?id=test"
    fake_finding.parameter.name = "id"
    fake_confirmed = [(fake_finding, "MySQL")]

    from sqli_recon.intelligence import ErrorDetector, SSTIDetector, CommandInjectionDetector
    monkeypatch.setattr(ErrorDetector, "test_findings",
                        lambda self, findings, **kw: fake_confirmed if findings else [])
    monkeypatch.setattr(SSTIDetector, "test_findings", lambda *a, **kw: [])
    monkeypatch.setattr(CommandInjectionDetector, "test_findings", lambda *a, **kw: [])

    client = MagicMock()
    found = run_layer_a(labels, base_url="http://x:8080", client=client)
    assert "ErrorDetector" in found
    assert ("/users", "GET", "id") in found["ErrorDetector"]
    assert found["SSTIDetector"] == set()
