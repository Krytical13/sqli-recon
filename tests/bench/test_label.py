import json
from pathlib import Path

from bench.label import Label, load_labels
from sqli_recon.models import ParamLocation, VulnType

FIXTURE = Path(__file__).parent / "fixtures" / "sample_labels.json"


def test_label_dataclass_fields():
    label = Label(
        app="x", url_path="/", method="GET", parameter="id",
        location=ParamLocation.QUERY, vuln_types=[VulnType.SQLI], context={},
    )
    assert label.app == "x"
    assert label.vuln_types == [VulnType.SQLI]


def test_load_labels_reads_json():
    labels = load_labels(FIXTURE)
    assert len(labels) == 2
    assert labels[0].parameter == "id"
    assert labels[0].vuln_types == [VulnType.SQLI]
    assert labels[1].vuln_types == []  # clean endpoint
    assert labels[1].context["note"] == "clean endpoint, no params"


def test_load_labels_rejects_unknown_vuln_type():
    import pytest
    bad = [{"app": "x", "url_path": "/", "method": "GET", "parameter": "id",
            "location": "query", "vuln_types": ["bogus"], "context": {}}]
    bad_path = FIXTURE.parent / "bad_labels.json"
    bad_path.write_text(json.dumps(bad))
    try:
        with pytest.raises(ValueError, match="bogus"):
            load_labels(bad_path)
    finally:
        bad_path.unlink()
