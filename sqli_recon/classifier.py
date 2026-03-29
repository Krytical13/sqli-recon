"""SQLi surface classifier - scores each parameter by injection likelihood."""

import re
import logging
from urllib.parse import urlparse

from sqli_recon.models import Finding, Endpoint, Parameter, ParamLocation

log = logging.getLogger(__name__)

# ----- Scoring weights -----

# Parameter names strongly associated with SQL queries.
# Each entry is (pattern, score_bonus, reason).
NAME_RULES = [
    # Direct ID lookups (WHERE id = X) - highest risk
    (re.compile(r"^id$", re.I), 0.45, "direct ID parameter - likely WHERE clause"),
    (re.compile(r"(?:_|^)id$", re.I), 0.40, "ID-suffix parameter - likely DB lookup"),
    (re.compile(r"^(?:uid|pid|cid|nid|sid|tid|rid)$", re.I), 0.40, "short ID parameter"),
    (re.compile(r"(?:user|item|product|order|category|post|comment|article|file|group|account|customer|invoice|session|transaction|msg|thread|parent|record|entry)[_\-]?id$", re.I),
     0.40, "entity ID parameter - direct DB lookup"),

    # Search / text input
    (re.compile(r"^(?:q|query|search|keyword|term|find|lookup|search_query|searchQuery|search_term|searchTerm|keywords)$", re.I),
     0.40, "search parameter - likely used in WHERE/LIKE clause"),

    # Sort / ORDER BY
    (re.compile(r"^(?:sort|order|orderby|order_by|sortby|sort_by|sortfield|sortField|sort_field|orderfield|sort_column|sortColumn)$", re.I),
     0.42, "sort parameter - likely ORDER BY injection point"),
    (re.compile(r"^(?:dir|direction|sort_dir|sortDir|sort_order|sortOrder|asc|desc)$", re.I),
     0.35, "sort direction - may be injected into ORDER BY"),

    # Filter / WHERE
    (re.compile(r"^(?:filter|where|column|col|field|table|condition|criteria)$", re.I),
     0.38, "filter parameter - likely used in WHERE clause"),
    (re.compile(r"^(?:type|category|cat|tag|label|status|state|group)$", re.I),
     0.28, "category/type parameter - likely WHERE clause"),

    # Pagination / LIMIT
    (re.compile(r"^(?:limit|offset|per_page|perPage|page_size|pageSize|skip|take|first|last|count|num)$", re.I),
     0.22, "pagination parameter - may reach LIMIT/OFFSET"),
    (re.compile(r"^(?:page|from|to|start|end)$", re.I),
     0.15, "range parameter"),

    # Auth / credential lookup
    (re.compile(r"^(?:username|user|uname|login|email|mail)$", re.I),
     0.32, "auth parameter - credential lookup query"),
    (re.compile(r"^(?:password|pass|passwd|pwd)$", re.I),
     0.28, "password parameter - auth query"),

    # Data fields that may reach INSERT/UPDATE
    (re.compile(r"^(?:name|fname|lname|first_name|last_name|firstname|lastname|title|subject)$", re.I),
     0.18, "data field - may reach INSERT/UPDATE"),
    (re.compile(r"^(?:description|desc|content|body|message|msg|comment|note|review|text)$", re.I),
     0.18, "text content field"),

    # Date/time (WHERE date BETWEEN)
    (re.compile(r"(?:date|time|timestamp|created|updated|modified|since|until)", re.I),
     0.15, "date parameter - may reach date comparison query"),

    # Numeric values
    (re.compile(r"^(?:price|amount|total|qty|quantity|cost|rate|score|rating)$", re.I),
     0.18, "numeric value - may reach comparison query"),

    # SQL keywords in param names (sometimes lazy devs use these)
    (re.compile(r"^(?:select|union|join|having|groupby|group_by)$", re.I),
     0.50, "SQL keyword as parameter name - strong injection indicator"),
]

# Location risk multipliers
LOCATION_WEIGHTS = {
    ParamLocation.QUERY: 1.0,
    ParamLocation.BODY: 1.0,
    ParamLocation.JSON: 0.95,
    ParamLocation.PATH: 0.90,
    ParamLocation.COOKIE: 0.70,
    ParamLocation.HEADER: 0.55,
}

# Technology signals from URL patterns
TECH_SIGNALS = [
    (re.compile(r"\.php", re.I), 0.08, "PHP endpoint - higher SQLi prevalence"),
    (re.compile(r"\.asp", re.I), 0.08, "ASP endpoint - higher SQLi prevalence"),
    (re.compile(r"\.jsp", re.I), 0.06, "JSP endpoint"),
    (re.compile(r"\.cgi", re.I), 0.06, "CGI endpoint"),
    (re.compile(r"/wp-", re.I), 0.05, "WordPress endpoint"),
    (re.compile(r"/xmlrpc", re.I), 0.04, "XML-RPC endpoint"),
]

# Response header signals
HEADER_SIGNALS = [
    ("X-Powered-By", re.compile(r"PHP", re.I), 0.05, "PHP detected via header"),
    ("X-Powered-By", re.compile(r"ASP", re.I), 0.05, "ASP detected via header"),
    ("Server", re.compile(r"Apache", re.I), 0.02, "Apache server"),
    ("Server", re.compile(r"IIS", re.I), 0.04, "IIS server - often paired with MSSQL"),
]


class Classifier:
    """Scores endpoint parameters by SQLi likelihood."""

    def classify(self, endpoints, tech_modifier=0.0, db_like_urls=None):
        """
        Score all parameters across all endpoints.

        Args:
            tech_modifier: Score adjustment from tech fingerprinting (+/- value)
            db_like_urls: Set of base_urls whose responses look like DB rows (bonus)

        Returns list of Finding objects sorted by score (highest first).
        """
        findings = []
        db_like_urls = db_like_urls or set()

        for endpoint in endpoints:
            if not endpoint.parameters:
                continue

            for param in endpoint.parameters:
                score, reasons = self._score_parameter(endpoint, param)

                # Tech fingerprint modifier
                if tech_modifier != 0:
                    score += tech_modifier

                # Response looks like DB rows
                if endpoint.base_url in db_like_urls:
                    score += 0.08
                    db_reason = endpoint.response_headers.get("_db_like", "structured data")
                    reasons.append(f"response looks like DB output ({db_reason})")

                if score > 0.05:
                    findings.append(Finding(
                        endpoint=endpoint,
                        parameter=param,
                        score=min(score, 1.0),
                        reasons=reasons,
                    ))

        findings.sort(key=lambda f: (-f.score, f.parameter.name))
        return findings

    def _score_parameter(self, endpoint, param):
        """Score a single parameter. Returns (score, reasons)."""
        score = 0.10  # Base score: any user-controlled input has some risk
        reasons = []

        # 1. Parameter name scoring
        name_score, name_reason = self._score_name(param.name)
        if name_score > 0:
            score += name_score
            reasons.append(name_reason)

        # 2. Value type scoring
        if param.param_type == "numeric":
            score += 0.12
            reasons.append("numeric value - common in WHERE id = X patterns")
        elif param.param_type == "uuid":
            score += 0.08
            reasons.append("UUID value - likely DB lookup")

        # 3. Location weighting
        location_weight = LOCATION_WEIGHTS.get(param.location, 0.8)
        if location_weight != 1.0:
            reasons.append(f"location={param.location.value} (weight: {location_weight:.2f})")
        score *= location_weight

        # 4. Technology signals from URL
        url = endpoint.url
        for pattern, bonus, reason in TECH_SIGNALS:
            if pattern.search(url):
                score += bonus
                reasons.append(reason)
                break  # Only count one tech signal

        # 5. Response header signals
        for header_name, pattern, bonus, reason in HEADER_SIGNALS:
            header_val = endpoint.response_headers.get(header_name, "")
            if pattern.search(header_val):
                score += bonus
                reasons.append(reason)
                break

        # 6. Endpoint type heuristics
        path = urlparse(url).path.lower()
        if any(seg in path for seg in ["/search", "/find", "/lookup", "/query"]):
            score += 0.08
            reasons.append("search-type endpoint")
        elif any(seg in path for seg in ["/login", "/auth", "/signin", "/register"]):
            score += 0.06
            reasons.append("authentication endpoint")
        elif any(seg in path for seg in ["/api/", "/rest/", "/v1/", "/v2/", "/v3/"]):
            score += 0.04
            reasons.append("API endpoint")
        elif any(seg in path for seg in ["/admin", "/manage", "/dashboard", "/internal"]):
            score += 0.05
            reasons.append("admin/internal endpoint")

        # 7. Path parameter bonus (path params are often IDs)
        if param.location == ParamLocation.PATH:
            score += 0.10
            reasons.append("path parameter - commonly used for direct DB lookups")

        return min(score, 1.0), reasons

    def _score_name(self, name):
        """Score a parameter by its name. Returns (bonus, reason)."""
        best_score = 0.0
        best_reason = ""

        for pattern, bonus, reason in NAME_RULES:
            if pattern.search(name):
                if bonus > best_score:
                    best_score = bonus
                    best_reason = reason

        return best_score, best_reason
