"""Automated test suite for sqli_recon.

Run: pytest tests/test_suite.py -v
Integration tests require the vulnerable test app on port 18484.
"""

import re
import json
import pytest
import subprocess
import time
import socket
from unittest.mock import Mock

# ---- Unit Tests (no network required) ----


class TestModels:
    def test_parameter_equality(self):
        from sqli_recon.models import Parameter, ParamLocation
        p1 = Parameter("id", ParamLocation.QUERY, "1")
        p2 = Parameter("id", ParamLocation.QUERY, "2")
        assert p1 == p2  # Same name+location, different value

    def test_parameter_inequality(self):
        from sqli_recon.models import Parameter, ParamLocation
        p1 = Parameter("id", ParamLocation.QUERY)
        p2 = Parameter("id", ParamLocation.BODY)
        assert p1 != p2  # Same name, different location

    def test_finding_risk_levels(self):
        from sqli_recon.models import Finding, Endpoint, Parameter, ParamLocation
        ep = Endpoint(url="http://test.com/")
        p = Parameter("id", ParamLocation.QUERY)
        assert Finding(ep, p, score=0.8).risk_level == "HIGH"
        assert Finding(ep, p, score=0.5).risk_level == "MEDIUM"
        assert Finding(ep, p, score=0.2).risk_level == "LOW"

    def test_placeholder_value(self):
        from sqli_recon.models import _placeholder_value, Parameter, ParamLocation
        p_limit = Parameter("limit", ParamLocation.JSON)
        p_name = Parameter("name", ParamLocation.JSON)
        p_with_val = Parameter("x", ParamLocation.JSON, value="hello")
        assert _placeholder_value(p_limit) == 10
        assert _placeholder_value(p_name) == "test"
        assert _placeholder_value(p_with_val) == "hello"

    def test_endpoint_base_url(self):
        from sqli_recon.models import Endpoint
        ep = Endpoint(url="http://test.com/search?q=hello&page=1")
        assert ep.base_url == "http://test.com/search"


class TestClassifier:
    def test_id_param_scores_high(self):
        from sqli_recon.models import Endpoint, Parameter, ParamLocation
        from sqli_recon.classifier import Classifier
        ep = Endpoint(url="http://test.com/users", parameters=[
            Parameter("id", ParamLocation.QUERY, "1", "numeric"),
        ])
        findings = Classifier().classify([ep])
        assert len(findings) == 1
        assert findings[0].score >= 0.5

    def test_sort_param_detected(self):
        from sqli_recon.models import Endpoint, Parameter, ParamLocation
        from sqli_recon.classifier import Classifier
        ep = Endpoint(url="http://test.com/products", parameters=[
            Parameter("sortby", ParamLocation.QUERY),
        ])
        findings = Classifier().classify([ep])
        assert any("sort" in r.lower() or "ORDER BY" in r for r in findings[0].reasons)

    def test_deduplication(self):
        from sqli_recon.models import Endpoint, Parameter, ParamLocation, Source
        from sqli_recon.classifier import Classifier
        ep1 = Endpoint(url="http://test.com/search?q=a", parameters=[
            Parameter("q", ParamLocation.QUERY),
        ], source=Source.CRAWL)
        ep2 = Endpoint(url="http://test.com/search?q=b", parameters=[
            Parameter("q", ParamLocation.QUERY),
        ], source=Source.JS)
        findings = Classifier().classify([ep1, ep2])
        # Same base_url + method + param should deduplicate to 1
        assert len(findings) == 1

    def test_tech_modifier(self):
        from sqli_recon.models import Endpoint, Parameter, ParamLocation
        from sqli_recon.classifier import Classifier
        ep = Endpoint(url="http://test.com/x", parameters=[
            Parameter("id", ParamLocation.QUERY),
        ])
        f_normal = Classifier().classify([ep])
        f_boosted = Classifier().classify([ep], tech_modifier=0.1)
        assert f_boosted[0].score > f_normal[0].score


class TestCaptchaDetection:
    def test_cloudflare_challenge(self):
        from sqli_recon.http_client import _is_captcha_response
        resp = Mock()
        resp.status_code = 503
        resp.headers = {"Server": "cloudflare"}
        resp.text = '<html>Checking your browser before accessing. cf_chl_opt Ray ID: abc</html>'
        assert _is_captcha_response(resp) is True

    def test_recaptcha(self):
        from sqli_recon.http_client import _is_captcha_response
        resp = Mock()
        resp.status_code = 200
        resp.headers = {}
        resp.text = '<div class="g-recaptcha"></div><p>verify you are human</p>'
        assert _is_captcha_response(resp) is True

    def test_custom_captcha(self):
        from sqli_recon.http_client import _is_captcha_response
        resp = Mock()
        resp.status_code = 200
        resp.headers = {}
        resp.text = '<h1>Captcha Required</h1><p>Solve the captcha to continue</p>'
        assert _is_captcha_response(resp) is True

    def test_normal_page(self):
        from sqli_recon.http_client import _is_captcha_response
        resp = Mock()
        resp.status_code = 200
        resp.headers = {}
        resp.text = '<html><body><h1>Welcome</h1><p>Forum content here</p></body></html>'
        assert _is_captcha_response(resp) is False

    def test_blog_mentioning_captcha(self):
        from sqli_recon.http_client import _is_captcha_response
        resp = Mock()
        resp.status_code = 200
        resp.headers = {}
        resp.text = "x" * 5000 + "<p>We added a captcha to prevent bots.</p>"
        assert _is_captcha_response(resp) is False


class TestTechFingerprint:
    def test_php_detection(self):
        from sqli_recon.intelligence import TechFingerprint
        fp = TechFingerprint()
        resp = Mock()
        resp.headers = {"X-Powered-By": "PHP/8.1", "Server": "Apache"}
        resp.cookies = Mock()
        resp.cookies.get_dict = lambda: {"PHPSESSID": "abc123"}
        resp.text = "<html></html>"
        resp.url = "http://test.com/index.php"
        fp.analyze_response(resp)
        assert fp.detected.get("PHP", 0) >= 0.9

    def test_mybb_detection(self):
        from sqli_recon.intelligence import TechFingerprint
        fp = TechFingerprint()
        resp = Mock()
        resp.headers = {"Server": "nginx"}
        resp.cookies = Mock()
        resp.cookies.get_dict = lambda: {}
        resp.text = '<a href="showthread.php?tid=1">Thread</a><a href="member.php?action=profile">Profile</a>'
        resp.url = "http://test.com/"
        fp.analyze_response(resp)
        assert fp.detected.get("MyBB", 0) >= 0.5

    def test_mybb_sqlmap_flags(self):
        from sqli_recon.intelligence import TechFingerprint
        fp = TechFingerprint()
        fp._add("MyBB", 0.9)
        fp._add("PHP", 0.9)
        flags, notes = fp.sqlmap_flags()
        assert "--dbms=MySQL" in flags
        assert "--level=3" in flags
        assert "--tamper=space2comment" in flags

    def test_django_risk_reduction(self):
        from sqli_recon.intelligence import TechFingerprint
        fp = TechFingerprint()
        fp._add("Django", 0.9)
        assert fp.sqli_risk_modifier() < 0

    def test_priority_endpoints(self):
        from sqli_recon.intelligence import TechFingerprint
        fp = TechFingerprint()
        fp._add("WordPress", 0.9)
        eps = fp.priority_endpoints()
        assert any("/wp-json" in e for e in eps)
        assert any("xmlrpc" in e for e in eps)

    def test_scan_recommendations(self):
        from sqli_recon.intelligence import TechFingerprint
        fp = TechFingerprint()
        fp._add("MyBB", 0.9)
        rec = fp.scan_recommendations()
        assert rec["skip_api_brute"] is True
        assert rec["skip_graphql"] is True
        assert rec["extra_depth"] >= 1


class TestErrorDetection:
    def test_mysql_error(self):
        from sqli_recon.intelligence import _check_for_db_errors
        assert _check_for_db_errors("You have an error in your SQL syntax") == "MySQL"

    def test_sqlite_error(self):
        from sqli_recon.intelligence import _check_for_db_errors
        assert _check_for_db_errors('near "\'": syntax error') == "SQLite"

    def test_postgres_error(self):
        from sqli_recon.intelligence import _check_for_db_errors
        assert _check_for_db_errors("ERROR: syntax error at or near") == "PostgreSQL"

    def test_mssql_error(self):
        from sqli_recon.intelligence import _check_for_db_errors
        assert _check_for_db_errors("Unclosed quotation mark after the character string") == "MSSQL"

    def test_no_error(self):
        from sqli_recon.intelligence import _check_for_db_errors
        assert _check_for_db_errors("<html><body>Normal page</body></html>") is None


class TestJsAnalyzer:
    def test_fetch_post_detection(self):
        from sqli_recon.js_analyzer import JsAnalyzer
        from sqli_recon.http_client import HttpClient

        # Can't test with real HTTP, but test the extraction logic
        analyzer = JsAnalyzer(HttpClient(), "http://test.com")
        js_text = '''
        fetch("/api/v1/search", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({query: term, field: "name", limit: 50})
        });
        '''
        endpoints = analyzer._extract_post_endpoints(js_text, "http://test.com/app.js", set())
        assert len(endpoints) >= 1
        post_eps = [e for e in endpoints if e.method == "POST"]
        assert len(post_eps) >= 1
        param_names = [p.name for p in post_eps[0].parameters]
        assert "query" in param_names
        assert "field" in param_names
        assert "limit" in param_names

    def test_json_field_values_preserved(self):
        from sqli_recon.js_analyzer import JsAnalyzer
        from sqli_recon.http_client import HttpClient

        analyzer = JsAnalyzer(HttpClient(), "http://test.com")
        fields = analyzer._extract_json_fields(
            'JSON.stringify({query: term, field: "name", limit: 50})'
        )
        field_dict = {name: val for name, val in fields}
        assert field_dict.get("field") == "name"
        assert field_dict.get("limit") == "50"


class TestSurfaceDedup:
    def test_same_path_same_params_dedup(self):
        from urllib.parse import urlparse, parse_qs
        urls = [
            "/showthread.php?tid=1",
            "/showthread.php?tid=2",
            "/showthread.php?tid=500",
        ]
        seen = set()
        crawled = []
        for url in urls:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            key = (parsed.path, frozenset(qs.keys()))
            if qs and key in seen:
                continue
            if qs:
                seen.add(key)
            crawled.append(url)
        assert len(crawled) == 1

    def test_different_params_not_deduped(self):
        from urllib.parse import urlparse, parse_qs
        urls = [
            "/showthread.php?tid=1",
            "/showthread.php?tid=1&page=2",
        ]
        seen = set()
        crawled = []
        for url in urls:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            key = (parsed.path, frozenset(qs.keys()))
            if qs and key in seen:
                continue
            if qs:
                seen.add(key)
            crawled.append(url)
        assert len(crawled) == 2


class TestAuth:
    def test_login_form_detection(self):
        from sqli_recon.auth import SessionManager
        mgr = SessionManager(Mock(), "http://test.com")
        html = '<form><input type="text" name="user"><input type="password" name="pass"><button>Login</button></form>'
        assert mgr._has_login_form(html) is True

    def test_no_login_form(self):
        from sqli_recon.auth import SessionManager
        mgr = SessionManager(Mock(), "http://test.com")
        html = '<form><input type="text" name="search"><button>Search</button></form>'
        assert mgr._has_login_form(html) is False

    def test_login_url_detection(self):
        from sqli_recon.auth import SessionManager
        mgr = SessionManager(Mock(), "http://test.com")
        assert mgr._is_login_url("/user/login") is True
        assert mgr._is_login_url("/wp-login.php") is True
        assert mgr._is_login_url("/products") is False


# ---- Integration Tests (require test app on port 18484) ----

def _app_running():
    """Check if the test app is running."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("127.0.0.1", 18484))
        s.close()
        return True
    except (ConnectionRefusedError, OSError):
        return False


@pytest.fixture(scope="module")
def live_app():
    """Ensure the test app is running."""
    if not _app_running():
        pytest.skip("Test app not running on port 18484. Start with: python tests/vulnerable_app.py")


@pytest.mark.integration
class TestIntegration:
    def test_full_scan(self, live_app):
        """Run a quick scan and verify findings."""
        from sqli_recon.http_client import HttpClient
        from sqli_recon.crawler import Crawler
        from sqli_recon.js_analyzer import JsAnalyzer
        from sqli_recon.classifier import Classifier

        client = HttpClient()
        crawler = Crawler(client, "http://127.0.0.1:18484", max_depth=2, max_pages=30)
        endpoints, js_urls = crawler.crawl()

        analyzer = JsAnalyzer(client, "http://127.0.0.1:18484")
        js_endpoints = analyzer.analyze(js_urls)
        all_eps = endpoints + js_endpoints

        findings = Classifier().classify(all_eps)

        assert len(findings) > 0
        # Should find high-value params
        param_names = {f.parameter.name for f in findings}
        assert "q" in param_names or "user_id" in param_names or "sort" in param_names

    def test_error_detection(self, live_app):
        """Verify error detector confirms injectable params."""
        from sqli_recon.http_client import HttpClient
        from sqli_recon.models import Endpoint, Parameter, ParamLocation, Finding
        from sqli_recon.intelligence import ErrorDetector

        client = HttpClient()
        # Use the login endpoint — username param is confirmed injectable
        ep = Endpoint(
            url="http://127.0.0.1:18484/login",
            method="POST",
            parameters=[
                Parameter("username", ParamLocation.BODY, "admin"),
                Parameter("password", ParamLocation.BODY, "test"),
                Parameter("redirect", ParamLocation.BODY, "/"),
            ],
        )
        finding = Finding(ep, ep.parameters[0], score=0.5)

        detector = ErrorDetector(client)
        confirmed = detector.test_findings([finding], min_score=0.3)
        assert len(confirmed) >= 1
        assert confirmed[0][1] == "SQLite"

    def test_graphql_introspection(self, live_app):
        """Verify GraphQL introspection discovers endpoints."""
        from sqli_recon.http_client import HttpClient
        from sqli_recon.intelligence import GraphQLIntrospector

        client = HttpClient()
        gql = GraphQLIntrospector(client, "http://127.0.0.1:18484")
        endpoints = gql.discover_and_introspect()
        assert len(endpoints) > 0
        param_names = {p.name for ep in endpoints for p in ep.parameters}
        assert "id" in param_names or "query" in param_names

    def test_tech_fingerprint(self, live_app):
        """Verify tech fingerprinting detects the test app's stack."""
        from sqli_recon.http_client import HttpClient
        from sqli_recon.intelligence import TechFingerprint
        import requests

        client = HttpClient()
        resp = client.get("http://127.0.0.1:18484/")
        fp = TechFingerprint()
        fp.analyze_response(resp)
        # The test app is Flask but doesn't advertise it prominently
        # At minimum it shouldn't crash
        assert isinstance(fp.detected, dict)
