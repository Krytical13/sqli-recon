"""Intelligence modules — error pre-detection, tech fingerprinting, response analysis, GraphQL."""

import re
import json
import logging
from urllib.parse import urlparse, urljoin, urlencode, parse_qs

from sqli_recon.models import Endpoint, Parameter, ParamLocation, Source

log = logging.getLogger(__name__)


# ============================================================
# 1. Error-based SQLi pre-detection
# ============================================================

# Database error patterns — if any appear in the response after sending a
# single quote, the parameter is almost certainly injectable.
DB_ERROR_PATTERNS = [
    # MySQL
    (re.compile(r"You have an error in your SQL syntax", re.I), "MySQL"),
    (re.compile(r"mysql_fetch|mysql_num_rows|mysql_query", re.I), "MySQL"),
    (re.compile(r"Warning.*?\Wmysqli?_", re.I), "MySQL"),
    (re.compile(r"MySQLSyntaxErrorException", re.I), "MySQL"),
    # PostgreSQL
    (re.compile(r"ERROR:\s+syntax error at or near", re.I), "PostgreSQL"),
    (re.compile(r"pg_query|pg_exec|pg_connect", re.I), "PostgreSQL"),
    (re.compile(r"PSQLException", re.I), "PostgreSQL"),
    (re.compile(r"unterminated quoted string", re.I), "PostgreSQL"),
    # SQLite
    (re.compile(r"SQLite.*?(?:error|warning)", re.I), "SQLite"),
    (re.compile(r"sqlite3\.OperationalError", re.I), "SQLite"),
    (re.compile(r"unrecognized token", re.I), "SQLite"),
    (re.compile(r"near \".*?\": syntax error", re.I), "SQLite"),
    # Microsoft SQL Server
    (re.compile(r"Unclosed quotation mark", re.I), "MSSQL"),
    (re.compile(r"Microsoft.*?ODBC.*?Driver", re.I), "MSSQL"),
    (re.compile(r"mssql_query", re.I), "MSSQL"),
    (re.compile(r"SqlException", re.I), "MSSQL"),
    (re.compile(r"Incorrect syntax near", re.I), "MSSQL"),
    # Oracle
    (re.compile(r"ORA-\d{5}", re.I), "Oracle"),
    (re.compile(r"oracle.*?error|oracle.*?driver", re.I), "Oracle"),
    (re.compile(r"quoted string not properly terminated", re.I), "Oracle"),
    # Generic
    (re.compile(r"SQL syntax.*?error", re.I), "Unknown"),
    (re.compile(r"SQL.*?error.*?syntax", re.I), "Unknown"),
    (re.compile(r"database error", re.I), "Unknown"),
    (re.compile(r"SQLSTATE\[", re.I), "Unknown"),
    (re.compile(r"java\.sql\.SQLException", re.I), "Java/JDBC"),
    (re.compile(r"PDOException", re.I), "PHP/PDO"),
]


class ErrorDetector:
    """
    Sends a single quote to high-scoring parameters and checks for DB errors.

    This is NOT exploitation — it's the same as typing ' in a search box.
    If the app returns a database error, the parameter is confirmed injectable.
    """

    def __init__(self, client):
        self.client = client

    def test_findings(self, findings, min_score=0.3, progress_callback=None):
        """
        Test high-scoring findings for error-based confirmation.
        Returns list of (finding, db_type) tuples for confirmed injectable params.
        """
        confirmed = []
        candidates = [f for f in findings if f.score >= min_score]

        # Deduplicate — don't test the same endpoint+param twice
        tested = set()

        for i, finding in enumerate(candidates):
            if progress_callback and (i + 1) % 3 == 0:
                progress_callback(i + 1, len(candidates))

            key = (finding.endpoint.base_url, finding.endpoint.method, finding.parameter.name)
            if key in tested:
                continue
            tested.add(key)

            db_type = self._test_param(finding)
            if db_type:
                confirmed.append((finding, db_type))

        if progress_callback:
            progress_callback(len(candidates), len(candidates))

        return confirmed

    def _test_param(self, finding):
        """Send a single quote and check for DB errors. Returns DB type or None."""
        ep = finding.endpoint
        param = finding.parameter
        probe_value = "'"

        try:
            if param.location == ParamLocation.QUERY:
                # Inject into query string
                parsed = urlparse(ep.url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[param.name] = [probe_value]
                probe_url = ep.base_url + "?" + urlencode(qs, doseq=True)
                resp = self.client.get(probe_url)

            elif param.location == ParamLocation.BODY:
                # Inject into form body
                data = {}
                for p in ep.parameters:
                    if p.location == ParamLocation.BODY:
                        data[p.name] = p.value or "test"
                data[param.name] = probe_value
                resp = self.client.post(ep.base_url, data=data)

            elif param.location == ParamLocation.JSON:
                # Inject into JSON body
                body = {}
                for p in ep.parameters:
                    if p.location == ParamLocation.JSON:
                        body[p.name] = p.value or "test"
                body[param.name] = probe_value
                resp = self.client.post(
                    ep.base_url, json=body,
                    headers={"Content-Type": "application/json"},
                )

            elif param.location == ParamLocation.PATH:
                # Inject into path segment — only replace in the path, not hostname
                parsed = urlparse(ep.url)
                if param.value and param.value in parsed.path:
                    new_path = parsed.path.replace(param.value, probe_value, 1)
                    from urllib.parse import urlunparse
                    probe_url = urlunparse((parsed.scheme, parsed.netloc, new_path,
                                            parsed.params, parsed.query, ""))
                    resp = self.client.get(probe_url)
                else:
                    return None

            else:
                return None

            if resp is None:
                return None

            return _check_for_db_errors(resp.text)

        except Exception as e:
            log.debug(f"Error testing {ep.base_url} param {param.name}: {e}")
            return None


def _check_for_db_errors(text):
    """Check response text for database error signatures. Returns DB type or None."""
    if not text:
        return None
    # Only check first 10KB to avoid scanning huge responses
    text = text[:10240]
    for pattern, db_type in DB_ERROR_PATTERNS:
        if pattern.search(text):
            return db_type
    return None


# ============================================================
# 2. Technology fingerprinting
# ============================================================

class TechFingerprint:
    """Identifies the backend technology stack from response characteristics."""

    def __init__(self):
        self.detected = {}  # tech_name -> confidence (0.0-1.0)
        self._checked = False

    def analyze_response(self, resp):
        """Analyze a single HTTP response for technology signals."""
        if resp is None:
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}
        cookies = resp.cookies.get_dict()
        body = resp.text[:5000] if resp.text else ""
        url = resp.url

        # ---- Headers ----
        powered = headers.get("x-powered-by", "")
        server = headers.get("server", "")

        if re.search(r"PHP", powered, re.I):
            self._add("PHP", 0.9)
        if re.search(r"ASP\.NET", powered, re.I):
            self._add("ASP.NET", 0.9)
        if re.search(r"Express", powered, re.I):
            self._add("Node.js/Express", 0.8)
        if re.search(r"JSP|Servlet", powered, re.I):
            self._add("Java", 0.8)

        if re.search(r"Apache", server, re.I):
            self._add("Apache", 0.5)
        if re.search(r"nginx", server, re.I):
            self._add("nginx", 0.5)
        if re.search(r"IIS", server, re.I):
            self._add("IIS", 0.7)
            self._add("ASP.NET", 0.4)
        if re.search(r"openresty", server, re.I):
            self._add("OpenResty/Lua", 0.6)

        # Django
        if "csrfmiddlewaretoken" in body or headers.get("x-frame-options") == "DENY":
            self._add("Django", 0.3)

        # ---- Cookies ----
        cookie_names = set(cookies.keys())
        if "PHPSESSID" in cookie_names:
            self._add("PHP", 0.9)
        if "ASP.NET_SessionId" in cookie_names or "ASPSESSIONID" in str(cookie_names).upper():
            self._add("ASP.NET", 0.9)
        if "JSESSIONID" in cookie_names:
            self._add("Java", 0.9)
        if "connect.sid" in cookie_names:
            self._add("Node.js/Express", 0.7)
        if "rack.session" in cookie_names:
            self._add("Ruby/Rails", 0.8)
        if "_rails_session" in cookie_names or any("_session" in c and "rails" in c.lower() for c in cookie_names):
            self._add("Ruby/Rails", 0.8)
        if "csrftoken" in cookie_names and "sessionid" in cookie_names:
            self._add("Django", 0.8)
        if "laravel_session" in cookie_names:
            self._add("Laravel", 0.9)
            self._add("PHP", 0.6)

        # ---- URL patterns ----
        path = urlparse(url).path.lower()
        if path.endswith(".php"):
            self._add("PHP", 0.9)
        elif path.endswith(".asp") or path.endswith(".aspx"):
            self._add("ASP.NET", 0.9)
        elif path.endswith(".jsp") or path.endswith(".do"):
            self._add("Java", 0.8)
        elif path.endswith(".cgi") or path.endswith(".pl"):
            self._add("Perl/CGI", 0.7)

        # ---- HTML meta / body patterns ----
        if re.search(r"wp-content|wp-includes|wordpress", body, re.I):
            self._add("WordPress", 0.9)
            self._add("PHP", 0.7)
        if re.search(r"Drupal|drupal\.js", body, re.I):
            self._add("Drupal", 0.8)
            self._add("PHP", 0.7)
        if re.search(r"mybb|member\.php\?action|showthread\.php", body, re.I):
            self._add("MyBB", 0.8)
            self._add("PHP", 0.7)
        if re.search(r"phpBB|viewtopic\.php", body, re.I):
            self._add("phpBB", 0.8)
            self._add("PHP", 0.7)

        self._checked = True

    def _add(self, tech, confidence):
        """Add/update a tech detection. Keeps highest confidence."""
        current = self.detected.get(tech, 0)
        self.detected[tech] = max(current, confidence)

    def sqli_risk_modifier(self):
        """
        Returns a score modifier based on detected technologies.
        Higher for PHP/ASP (historically more SQLi), lower for
        frameworks with ORM defaults (Django, Rails, Laravel).
        """
        modifier = 0.0

        # High risk — languages/frameworks with historically more SQLi
        if self.detected.get("PHP", 0) > 0.5:
            modifier += 0.06
        if self.detected.get("ASP.NET", 0) > 0.5:
            modifier += 0.06
        if self.detected.get("Java", 0) > 0.5:
            modifier += 0.03
        if self.detected.get("WordPress", 0) > 0.5:
            modifier += 0.04
        if self.detected.get("MyBB", 0) > 0.5:
            modifier += 0.04

        # Lower risk — frameworks that default to parameterized queries
        if self.detected.get("Django", 0) > 0.5:
            modifier -= 0.05
        if self.detected.get("Ruby/Rails", 0) > 0.5:
            modifier -= 0.05
        if self.detected.get("Laravel", 0) > 0.5:
            modifier -= 0.03  # PHP but with ORM

        return modifier

    def summary(self):
        """Return detected technologies sorted by confidence."""
        return sorted(self.detected.items(), key=lambda x: -x[1])


# ============================================================
# 3. Response content analysis
# ============================================================

class ResponseAnalyzer:
    """Analyzes response content to determine if an endpoint likely hits a database."""

    @staticmethod
    def looks_like_db_rows(resp):
        """
        Check if a response looks like database query results.
        Returns (is_db_like, reason) tuple.
        """
        if resp is None:
            return False, ""

        content_type = resp.headers.get("Content-Type", "")

        # JSON array of objects = very likely DB rows
        if "application/json" in content_type:
            try:
                data = resp.json()
                if isinstance(data, list) and len(data) >= 2:
                    # Check if items are objects with consistent keys
                    if all(isinstance(item, dict) for item in data[:5]):
                        keys = set(data[0].keys())
                        consistent = all(set(d.keys()) == keys for d in data[:5])
                        if consistent and len(keys) >= 2:
                            return True, f"JSON array of {len(data)} objects with consistent keys ({', '.join(sorted(keys)[:5])})"

                # Nested: {"results": [...], "data": [...], "items": [...]}
                if isinstance(data, dict):
                    for key in ("results", "data", "items", "rows", "records", "entries", "list", "objects"):
                        inner = data.get(key)
                        if isinstance(inner, list) and len(inner) >= 2:
                            if all(isinstance(item, dict) for item in inner[:5]):
                                return True, f"JSON .{key}[] array of {len(inner)} objects"
            except (ValueError, TypeError):
                pass

        # HTML table with multiple rows = might be DB output
        if "text/html" in content_type and resp.text:
            text = resp.text[:20000]
            tr_count = text.count("<tr")
            if tr_count >= 4:
                th_count = text.count("<th")
                if th_count >= 2:
                    return True, f"HTML table with {th_count} columns, {tr_count} rows"

        return False, ""


# ============================================================
# 4. GraphQL introspection
# ============================================================

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args {
          name
          type { name kind ofType { name kind } }
        }
      }
    }
  }
}
""".strip()

# Common GraphQL endpoint paths
GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/api/graphql", "/gql",
    "/v1/graphql", "/v2/graphql", "/query",
]


class GraphQLIntrospector:
    """Detects GraphQL endpoints and extracts all arguments via introspection."""

    def __init__(self, client, target_url):
        self.client = client
        self.target_url = target_url

    def discover_and_introspect(self, known_endpoints=None, progress_callback=None):
        """
        Try known GraphQL paths + any /graphql endpoints from crawling.
        Returns list of Endpoints with all discovered arguments.
        """
        endpoints = []
        parsed = urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Combine known paths with any discovered endpoints
        paths_to_try = list(GRAPHQL_PATHS)
        if known_endpoints:
            for ep in known_endpoints:
                ep_path = urlparse(ep.url).path.lower()
                if "graphql" in ep_path or "gql" in ep_path:
                    paths_to_try.append(urlparse(ep.url).path)

        # Deduplicate
        paths_to_try = list(dict.fromkeys(paths_to_try))

        for i, path in enumerate(paths_to_try):
            if progress_callback and (i + 1) % 3 == 0:
                progress_callback(i + 1, len(paths_to_try))

            url = base + path
            result = self._try_introspection(url)
            if result:
                endpoints.extend(result)
                break  # Found it, don't need to try more paths

        return endpoints

    def _try_introspection(self, url):
        """Attempt GraphQL introspection at a URL. Returns list of Endpoints or None."""
        resp = self.client.post(
            url,
            json={"query": INTROSPECTION_QUERY},
            headers={"Content-Type": "application/json"},
        )
        if resp is None or resp.status_code != 200:
            return None

        try:
            data = resp.json()
        except (ValueError, TypeError):
            return None

        schema = data.get("data", {}).get("__schema")
        if not schema:
            return None

        log.info(f"GraphQL introspection succeeded at {url}")
        return self._parse_schema(url, schema)

    def _parse_schema(self, url, schema):
        """Extract all query/mutation arguments from a GraphQL schema."""
        endpoints = []
        query_type_name = schema.get("queryType", {}).get("name", "Query")
        mutation_type_name = (schema.get("mutationType") or {}).get("name", "Mutation")

        for type_def in schema.get("types", []):
            type_name = type_def.get("name", "")
            if type_name.startswith("__"):
                continue  # Skip introspection types

            is_query = type_name == query_type_name
            is_mutation = type_name == mutation_type_name
            if not is_query and not is_mutation:
                continue

            for field in type_def.get("fields", []):
                field_name = field.get("name", "")
                args = field.get("args", [])
                if not args:
                    continue

                params = []
                for arg in args:
                    arg_name = arg.get("name", "")
                    arg_type = arg.get("type", {})
                    # Determine param type
                    type_name_inner = _graphql_type_name(arg_type)
                    param_type = "numeric" if type_name_inner in ("Int", "Float", "ID") else "string"

                    params.append(Parameter(
                        name=arg_name,
                        location=ParamLocation.JSON,
                        value="",
                        param_type=param_type,
                    ))

                method = "POST"
                operation = "query" if is_query else "mutation"

                endpoints.append(Endpoint(
                    url=url,
                    method=method,
                    parameters=params,
                    content_type="application/json",
                    source=Source.CRAWL,
                    body_template=f'{{"query": "{operation} {{ {field_name}(...) {{ ... }} }}"}}',
                ))

        return endpoints


def _graphql_type_name(type_obj):
    """Extract the base type name from a GraphQL type (unwrapping NonNull/List)."""
    if not type_obj:
        return "String"
    name = type_obj.get("name")
    if name:
        return name
    of_type = type_obj.get("ofType")
    if of_type:
        return _graphql_type_name(of_type)
    return "String"
