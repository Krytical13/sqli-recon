"""Static label map for DVWA. The vulnerability set is stable across releases."""
from typing import List

from bench.label import Label
from sqli_recon.models import ParamLocation, VulnType


# DVWA's vulnerability pages — these are stable across versions.
# Each entry: (path, method, parameter, location, vuln_types, context)
DVWA_VULN_MAP = [
    # SQL Injection
    ("/vulnerabilities/sqli/",       "GET",  "id", ParamLocation.QUERY,
     [VulnType.SQLI], {"category": "sqli"}),
    ("/vulnerabilities/sqli_blind/", "GET",  "id", ParamLocation.QUERY,
     [VulnType.SQLI], {"category": "sqli_blind"}),

    # Command Injection
    ("/vulnerabilities/exec/", "POST", "ip", ParamLocation.BODY,
     [VulnType.CMDI], {"category": "exec"}),

    # Clean endpoints (DVWA static pages, no vuln)
    ("/index.php",        "GET", "", ParamLocation.QUERY, [], {"clean": True}),
    ("/about.php",        "GET", "", ParamLocation.QUERY, [], {"clean": True}),
    ("/instructions.php", "GET", "", ParamLocation.QUERY, [], {"clean": True}),
]


def extract() -> List[Label]:
    """Return DVWA labels. Map is static — DVWA's vuln set is stable."""
    labels = []
    for path, method, param, location, vuln_types, context in DVWA_VULN_MAP:
        labels.append(Label(
            app="dvwa", url_path=path, method=method, parameter=param,
            location=location, vuln_types=vuln_types, context=context,
        ))
    return labels
