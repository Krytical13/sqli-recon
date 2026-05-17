from unittest.mock import patch, MagicMock

from bench.e2e_runner import run_layer_b


def test_run_layer_b_groups_by_confirmed_type(monkeypatch):
    """Layer B parses the scan's findings into per-detector found-sets."""
    from sqli_recon.models import Endpoint, Parameter, Finding, ParamLocation, VulnType

    f1 = Finding(
        endpoint=Endpoint(url="http://x:8080/users?id=1", method="GET",
                          parameters=[Parameter("id", ParamLocation.QUERY, "1")]),
        parameter=Parameter("id", ParamLocation.QUERY, "1"),
        score=0.95,
        confirmed_types={VulnType.SQLI},
    )
    f2 = Finding(
        endpoint=Endpoint(url="http://x:8080/render?tpl=hi", method="GET",
                          parameters=[Parameter("tpl", ParamLocation.QUERY, "hi")]),
        parameter=Parameter("tpl", ParamLocation.QUERY, "hi"),
        score=0.95,
        confirmed_types={VulnType.SSTI},
    )

    monkeypatch.setattr("bench.e2e_runner._invoke_scan", lambda *a, **kw: [f1, f2])

    found = run_layer_b(base_url="http://x:8080")
    assert ("/users", "GET", "id") in found["ErrorDetector"]
    assert ("/render", "GET", "tpl") in found["SSTIDetector"]
