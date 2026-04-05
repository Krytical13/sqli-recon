"""
Test sites for recon-gather validation.

Spins up a Flask server with multiple routes simulating real-world web app
patterns: vulnerable forms, APIs, WAF behavior, SPAs, leaked secrets,
missing security headers, error disclosure, etc.

Usage:
    python tests/test_sites.py          # Runs on port 5199
    python tests/test_sites.py 8888     # Custom port
"""

import json
import sys
import time
import re
from functools import wraps
from flask import Flask, request, jsonify, make_response, redirect, url_for

app = Flask(__name__)

# ---------------------------------------------------------------------------
# WAF simulation
# ---------------------------------------------------------------------------

WAF_PATTERNS = [
    re.compile(r"(?:union\s+select|select\s+.*\s+from)", re.I),
    re.compile(r"(?:'\s*or\s+.*=|'\s*--)", re.I),
    re.compile(r"<script", re.I),
    re.compile(r"\{\{.*\}\}", re.I),  # SSTI
    re.compile(r";\s*(?:ls|cat|id|whoami|wget|curl)\b", re.I),  # cmdi
]

WAF_REQUEST_LOG = []
WAF_BLOCK_COUNT = 0


def waf_check():
    """Simulate a basic WAF — blocks obvious attack patterns."""
    global WAF_BLOCK_COUNT
    # Check all input sources
    check_values = []
    check_values.extend(request.args.values())
    check_values.extend(request.form.values())
    if request.is_json and isinstance(request.json, dict):
        check_values.extend(str(v) for v in request.json.values())
    for header_val in [request.headers.get("User-Agent", ""),
                       request.headers.get("Referer", "")]:
        check_values.append(header_val)

    for val in check_values:
        for pattern in WAF_PATTERNS:
            if pattern.search(str(val)):
                WAF_BLOCK_COUNT += 1
                WAF_REQUEST_LOG.append({
                    "time": time.time(),
                    "path": request.path,
                    "blocked_value": str(val)[:100],
                    "pattern": pattern.pattern,
                })
                resp = make_response(
                    "<html><head><title>Access Denied</title></head>"
                    "<body><h1>403 Forbidden</h1>"
                    "<p>Your request has been blocked by the Web Application Firewall.</p>"
                    "<p>Rule ID: WAF-2024-0042</p>"
                    "<p>If you believe this is an error, contact security@testcorp.internal</p>"
                    "</body></html>",
                    403
                )
                resp.headers["Server"] = "TestWAF/2.1"
                resp.headers["X-WAF-Block"] = "true"
                return resp
    return None


def add_standard_headers(resp):
    """Add realistic response headers."""
    resp.headers["Server"] = "Apache/2.4.52 (Ubuntu)"
    resp.headers["X-Powered-By"] = "PHP/8.1.2"
    return resp


def add_secure_headers(resp):
    """Add proper security headers."""
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-XSS-Protection"] = "1; mode=block"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=()"
    return resp


def add_insecure_headers(resp):
    """Intentionally missing/bad security headers."""
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "*"
    # Deliberately missing: HSTS, CSP, X-Frame-Options, etc.
    return resp


# ---------------------------------------------------------------------------
# Site 1: Classic PHP-style vulnerable app (insecure headers, SQL errors)
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    resp = make_response("""<!DOCTYPE html>
<html>
<head><title>TestCorp Internal Portal</title></head>
<body>
    <h1>TestCorp Employee Portal</h1>
    <nav>
        <a href="/login">Login</a> |
        <a href="/search">Search</a> |
        <a href="/products">Products</a> |
        <a href="/admin/dashboard">Admin</a> |
        <a href="/api/v1/docs">API Docs</a> |
        <a href="/upload">Upload</a> |
        <a href="/secure/profile">Profile</a>
    </nav>
    <!-- TODO: Remove debug endpoint before production -->
    <!-- Internal API: /api/internal/debug -->
    <!-- Staging: https://staging.testcorp.internal:8443 -->
    <script src="/static/js/app.js"></script>
    <script src="/static/js/api-client.js"></script>
    <script>
        var API_BASE = "/api/v1";
        fetch("/api/v1/config").then(r => r.json());
    </script>
</body>
</html>""")
    resp = add_standard_headers(resp)
    resp = add_insecure_headers(resp)
    resp.headers["Set-Cookie"] = "session=abc123def456; Path=/"
    return resp


@app.route("/login", methods=["GET", "POST"])
def login():
    blocked = waf_check()
    if blocked:
        return blocked

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # Simulate SQL error on bad input
        if "'" in username:
            resp = make_response(
                "<html><body>"
                "<h1>Application Error</h1>"
                "<pre>Warning: mysqli_query(): You have an error in your SQL syntax; "
                f"check the manual near ''{username}'' at line 1 in "
                "/var/www/html/testcorp/auth/login.php on line 42</pre>"
                "<p>Debug: SELECT * FROM users WHERE username='" + username.replace("<", "&lt;") + "' "
                "AND password='" + password.replace("<", "&lt;") + "'</p>"
                "</body></html>",
                500
            )
            resp = add_standard_headers(resp)
            return resp

        resp = make_response(redirect("/dashboard"))
        resp.headers["Set-Cookie"] = (
            f"PHPSESSID=a1b2c3d4e5f6; Path=/; "
            # Intentionally missing HttpOnly, Secure, SameSite
        )
        return resp

    resp = make_response("""<!DOCTYPE html>
<html>
<head><title>Login - TestCorp</title></head>
<body>
    <h2>Employee Login</h2>
    <form method="POST" action="/login">
        <label>Username: <input type="text" name="username"></label><br>
        <label>Password: <input type="password" name="password"></label><br>
        <input type="hidden" name="csrf_token" value="a1b2c3d4e5f6789">
        <input type="hidden" name="redirect" value="/dashboard">
        <button type="submit">Login</button>
    </form>
    <p><a href="/forgot-password">Forgot password?</a></p>
</body>
</html>""")
    resp = add_standard_headers(resp)
    return resp


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "")
        resp = make_response(f"<html><body><p>If {email} exists, a reset link was sent.</p></body></html>")
        resp = add_standard_headers(resp)
        return resp

    resp = make_response("""<html><body>
    <h2>Reset Password</h2>
    <form method="POST">
        <label>Email: <input type="email" name="email"></label>
        <button type="submit">Reset</button>
    </form>
    </body></html>""")
    resp = add_standard_headers(resp)
    return resp


@app.route("/search")
def search():
    blocked = waf_check()
    if blocked:
        return blocked

    q = request.args.get("q", "")
    category = request.args.get("category", "all")
    sort = request.args.get("sort", "relevance")
    page = request.args.get("page", "1")
    limit = request.args.get("limit", "20")

    # Simulate SQL error on sort parameter injection
    if sort not in ("relevance", "date", "price", "name"):
        resp = make_response(
            "<html><body>"
            "<pre>ERROR: syntax error at or near \"" + sort.replace("<", "&lt;") + "\"\n"
            "LINE 1: SELECT * FROM products ORDER BY " + sort.replace("<", "&lt;") + "\n"
            "HINT: Check your query near the ORDER BY clause.\n"
            "PostgreSQL 14.2</pre>"
            "</body></html>",
            500
        )
        resp = add_standard_headers(resp)
        return resp

    results = [
        {"id": 1, "name": "Widget A", "price": 29.99, "category": category},
        {"id": 2, "name": "Widget B", "price": 49.99, "category": category},
        {"id": 3, "name": "Gadget C", "price": 99.99, "category": category},
    ]

    resp = make_response(f"""<html><body>
    <h2>Search Results for "{q}"</h2>
    <form method="GET" action="/search">
        <input type="text" name="q" value="{q}">
        <select name="category">
            <option value="all">All</option>
            <option value="electronics">Electronics</option>
            <option value="clothing">Clothing</option>
        </select>
        <select name="sort">
            <option value="relevance">Relevance</option>
            <option value="price">Price</option>
            <option value="date">Date</option>
        </select>
        <input type="hidden" name="limit" value="{limit}">
        <button>Search</button>
    </form>
    <div class="results">
        {"".join(f'<div class="product"><a href="/products/{r["id"]}">{r["name"]}</a> - ${r["price"]}</div>' for r in results)}
    </div>
    <a href="/search?q={q}&page={int(page)+1}&sort={sort}&limit={limit}">Next</a>
    </body></html>""")
    resp = add_standard_headers(resp)
    return resp


@app.route("/products/<int:product_id>")
def product_detail(product_id):
    blocked = waf_check()
    if blocked:
        return blocked

    resp = make_response(f"""<html><body>
    <h2>Product #{product_id}</h2>
    <p>Widget {product_id}</p>
    <p>Price: $29.99</p>
    <form method="POST" action="/api/v1/cart/add">
        <input type="hidden" name="product_id" value="{product_id}">
        <input type="number" name="quantity" value="1" min="1">
        <input type="hidden" name="price" value="29.99">
        <button>Add to Cart</button>
    </form>
    <h3>Reviews</h3>
    <form method="POST" action="/api/v1/reviews">
        <input type="hidden" name="product_id" value="{product_id}">
        <input type="number" name="rating" value="5" min="1" max="5">
        <textarea name="comment" placeholder="Write a review..."></textarea>
        <button>Submit Review</button>
    </form>
    </body></html>""")
    resp = add_standard_headers(resp)
    return resp


@app.route("/products")
def product_list():
    category = request.args.get("category", "all")
    sort_by = request.args.get("sort_by", "name")
    order = request.args.get("order", "asc")

    resp = make_response(f"""<html><body>
    <h2>Products</h2>
    <a href="/products?category=electronics&sort_by=price&order=asc">Electronics</a> |
    <a href="/products?category=clothing&sort_by=name&order=desc">Clothing</a>
    <div>
        <a href="/products/1">Widget A</a><br>
        <a href="/products/2">Widget B</a><br>
        <a href="/products/3">Gadget C</a>
    </div>
    </body></html>""")
    resp = add_standard_headers(resp)
    return resp


# ---------------------------------------------------------------------------
# Site 2: REST API with JSON endpoints
# ---------------------------------------------------------------------------

@app.route("/api/v1/docs")
def api_docs():
    resp = make_response("""<html><body>
    <h1>TestCorp API v1</h1>
    <h3>Endpoints:</h3>
    <ul>
        <li>GET /api/v1/users?role=admin&limit=50</li>
        <li>GET /api/v1/users/:id</li>
        <li>POST /api/v1/users (JSON body)</li>
        <li>GET /api/v1/orders?status=pending&user_id=123</li>
        <li>POST /api/v1/orders</li>
        <li>GET /api/v1/reports?type=sales&date_from=2024-01-01&date_to=2024-12-31</li>
        <li>GET /api/v1/config</li>
    </ul>
    <script>
        // API client initialization
        const API_BASE = "/api/v1";

        async function getUsers(role, limit) {
            return fetch(`/api/v1/users?role=${role}&limit=${limit}`);
        }

        async function createUser(data) {
            return fetch("/api/v1/users", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({
                    username: data.username,
                    email: data.email,
                    role: data.role,
                    department: data.department
                })
            });
        }

        async function searchOrders(params) {
            const url = new URLSearchParams();
            url.append("status", params.status);
            url.append("user_id", params.userId);
            url.append("sort", params.sort);
            return fetch(`/api/v1/orders?${url}`);
        }

        async function submitReport(reportData) {
            return fetch("/api/v1/reports/generate", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({
                    report_type: reportData.type,
                    date_range: reportData.range,
                    filters: reportData.filters,
                    output_format: "pdf"
                })
            });
        }

        // Webhook config
        axios.post("/api/v1/webhooks", {
            url: "https://hooks.example.com/notify",
            events: ["order.created", "user.registered"],
            secret: "whsec_testkey123"
        });
    </script>
    </body></html>""")
    resp = add_standard_headers(resp)
    return resp


@app.route("/api/v1/users", methods=["GET", "POST"])
def api_users():
    blocked = waf_check()
    if blocked:
        return blocked

    if request.method == "POST":
        data = request.json or {}
        resp = jsonify({"id": 42, "status": "created", **data})
        resp.status_code = 201
        return resp

    role = request.args.get("role", "")
    limit = request.args.get("limit", "50")

    users = [
        {"id": 1, "username": "admin", "email": "admin@testcorp.internal",
         "role": "admin", "department": "IT"},
        {"id": 2, "username": "jsmith", "email": "john.smith@testcorp.internal",
         "role": role or "user", "department": "Sales"},
        {"id": 3, "username": "mjones", "email": "mary.jones@testcorp.internal",
         "role": "user", "department": "HR"},
    ]
    resp = jsonify({"users": users[:int(limit)], "total": len(users)})
    resp = add_insecure_headers(resp)
    return resp


@app.route("/api/v1/users/<int:user_id>")
def api_user_detail(user_id):
    blocked = waf_check()
    if blocked:
        return blocked

    # IDOR — no auth check
    user = {
        "id": user_id,
        "username": f"user{user_id}",
        "email": f"user{user_id}@testcorp.internal",
        "role": "admin" if user_id == 1 else "user",
        "phone": "+1-555-0100",
        "ssn_last4": "1234",
        "created": "2024-01-15T10:30:00Z",
    }
    resp = jsonify(user)
    resp = add_insecure_headers(resp)
    return resp


@app.route("/api/v1/orders", methods=["GET", "POST"])
def api_orders():
    blocked = waf_check()
    if blocked:
        return blocked

    status = request.args.get("status", "all")
    user_id = request.args.get("user_id", "")
    sort = request.args.get("sort", "date")

    orders = [
        {"id": 1001, "user_id": int(user_id or 1), "total": 129.99,
         "status": status if status != "all" else "shipped"},
        {"id": 1002, "user_id": int(user_id or 2), "total": 59.99,
         "status": "pending"},
    ]
    resp = jsonify({"orders": orders})
    resp = add_insecure_headers(resp)
    return resp


@app.route("/api/v1/reports")
def api_reports():
    report_type = request.args.get("type", "")
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")
    format_ = request.args.get("format", "json")

    resp = jsonify({
        "report_type": report_type,
        "period": f"{date_from} to {date_to}",
        "data": [
            {"month": "2024-01", "revenue": 45000, "orders": 120},
            {"month": "2024-02", "revenue": 52000, "orders": 145},
        ]
    })
    return resp


@app.route("/api/v1/reports/generate", methods=["POST"])
def api_reports_generate():
    data = request.json or {}
    resp = jsonify({"status": "queued", "report_id": "rpt_abc123", **data})
    return resp


@app.route("/api/v1/cart/add", methods=["POST"])
def api_cart_add():
    blocked = waf_check()
    if blocked:
        return blocked

    product_id = request.form.get("product_id", "")
    quantity = request.form.get("quantity", "1")
    price = request.form.get("price", "0")

    resp = jsonify({"status": "added", "product_id": product_id,
                     "quantity": quantity, "price": price})
    return resp


@app.route("/api/v1/reviews", methods=["POST"])
def api_reviews():
    blocked = waf_check()
    if blocked:
        return blocked

    resp = jsonify({"status": "submitted", "review_id": 42})
    return resp


@app.route("/api/v1/config")
def api_config():
    # Intentional info leak
    resp = jsonify({
        "api_version": "1.0.3",
        "environment": "production",
        "debug": True,
        "database": {
            "host": "db-prod-01.testcorp.internal",
            "port": 5432,
            "name": "testcorp_prod"
        },
        "redis": "redis://cache-01.testcorp.internal:6379/0",
        "features": {"new_search": True, "v2_api": False},
        "sentry_dsn": "https://abc123@sentry.testcorp.internal/5",
        "internal_api": "https://10.0.1.50:8443/internal",
    })
    resp = add_insecure_headers(resp)
    return resp


@app.route("/api/v1/webhooks", methods=["POST"])
def api_webhooks():
    data = request.json or {}
    resp = jsonify({"id": "wh_001", "status": "active", **data})
    resp.status_code = 201
    return resp


@app.route("/api/internal/debug")
def api_debug():
    """Intentionally leaked debug endpoint."""
    resp = jsonify({
        "server": "app-node-03.testcorp.internal",
        "ip": "10.0.1.23",
        "uptime": 847293,
        "connections": {
            "postgres": "postgres://app_user:s3cretP4ss@db-prod-01.testcorp.internal:5432/testcorp_prod",
            "redis": "redis://cache-01.testcorp.internal:6379",
            "elasticsearch": "http://10.0.1.40:9200"
        },
        "env": {
            "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
            "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "STRIPE_KEY": "sk_test_FAKE_KEY_FOR_TESTING_ONLY",
            "JWT_SECRET": "super_secret_jwt_key_do_not_share",
            "DATABASE_URL": "postgres://app_user:s3cretP4ss@db-prod-01.testcorp.internal:5432/testcorp_prod",
        },
        "stack_trace": "Traceback (most recent call last):\n  File \"/var/www/html/testcorp/app.py\", line 42\n    raise ValueError('debug mode active')"
    })
    return resp


# ---------------------------------------------------------------------------
# Site 3: Admin panel (behind WAF)
# ---------------------------------------------------------------------------

@app.route("/admin/dashboard")
def admin_dashboard():
    resp = make_response("""<html><body>
    <h1>Admin Dashboard</h1>
    <nav>
        <a href="/admin/users?filter=active&sort=last_login">Users</a> |
        <a href="/admin/logs?level=error&since=2024-01-01">Logs</a> |
        <a href="/admin/settings">Settings</a> |
        <a href="/admin/export?format=csv&table=users">Export</a> |
        <a href="/admin/sql-console">SQL Console</a>
    </nav>
    <iframe src="/admin/stats?period=30d"></iframe>
    </body></html>""")
    resp = add_standard_headers(resp)
    return resp


@app.route("/admin/users")
def admin_users():
    blocked = waf_check()
    if blocked:
        return blocked

    filter_ = request.args.get("filter", "all")
    sort = request.args.get("sort", "id")
    search = request.args.get("search", "")

    resp = make_response(f"""<html><body>
    <h2>User Management</h2>
    <form method="GET">
        <input type="text" name="search" value="{search}" placeholder="Search users...">
        <select name="filter"><option value="active">Active</option><option value="inactive">Inactive</option></select>
        <select name="sort"><option value="id">ID</option><option value="last_login">Last Login</option></select>
        <button>Filter</button>
    </form>
    <table>
        <tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr>
        <tr><td>1</td><td>admin</td><td>admin@testcorp.internal</td><td>admin</td></tr>
        <tr><td>2</td><td>jsmith</td><td>john.smith@testcorp.internal</td><td>user</td></tr>
    </table>
    </body></html>""")
    resp = add_standard_headers(resp)
    return resp


@app.route("/admin/logs")
def admin_logs():
    level = request.args.get("level", "all")
    since = request.args.get("since", "")
    source = request.args.get("source", "")

    resp = make_response(f"""<html><body>
    <h2>Application Logs</h2>
    <form method="GET">
        <select name="level"><option>error</option><option>warn</option><option>info</option></select>
        <input type="date" name="since" value="{since}">
        <input type="text" name="source" value="{source}" placeholder="Source filter...">
        <button>Filter</button>
    </form>
    <pre>[ERROR] 2024-03-15 10:42:11 - PSQLException: unterminated quoted string at position 42
[ERROR] 2024-03-15 10:41:08 - java.sql.SQLException: Column 'user_input' not found
[WARN]  2024-03-15 10:40:55 - Rate limit exceeded for IP 192.168.1.100</pre>
    </body></html>""")
    resp = add_standard_headers(resp)
    return resp


@app.route("/admin/export")
def admin_export():
    blocked = waf_check()
    if blocked:
        return blocked

    format_ = request.args.get("format", "csv")
    table = request.args.get("table", "")
    columns = request.args.get("columns", "*")
    where = request.args.get("where", "")

    resp = make_response(f"id,username,email\n1,admin,admin@testcorp.internal\n")
    resp.headers["Content-Type"] = "text/csv"
    resp.headers["Content-Disposition"] = f'attachment; filename="{table}_export.csv"'
    return resp


@app.route("/admin/settings", methods=["GET", "POST"])
def admin_settings():
    if request.method == "POST":
        resp = make_response(redirect("/admin/settings"))
        return resp

    resp = make_response("""<html><body>
    <h2>System Settings</h2>
    <form method="POST">
        <label>Site Title: <input type="text" name="site_title" value="TestCorp Portal"></label><br>
        <label>Admin Email: <input type="email" name="admin_email" value="admin@testcorp.internal"></label><br>
        <label>DB Host: <input type="text" name="db_host" value="db-prod-01.testcorp.internal"></label><br>
        <label>Debug Mode: <select name="debug"><option value="1" selected>On</option><option value="0">Off</option></select></label><br>
        <label>Session Timeout: <input type="number" name="session_timeout" value="3600"></label><br>
        <input type="hidden" name="csrf" value="x9y8z7w6v5u4t3s2r1">
        <button>Save</button>
    </form>
    </body></html>""")
    resp = add_standard_headers(resp)
    return resp


@app.route("/admin/sql-console", methods=["GET", "POST"])
def sql_console():
    """Intentionally dangerous endpoint."""
    blocked = waf_check()
    if blocked:
        return blocked

    if request.method == "POST":
        query = request.form.get("query", "")
        resp = make_response(f"""<html><body>
        <h2>SQL Console</h2>
        <form method="POST">
            <textarea name="query" rows="5" cols="80">{query}</textarea><br>
            <button>Execute</button>
        </form>
        <pre>Query: {query}
Result: 3 rows returned
| id | username | email |
| 1  | admin    | admin@testcorp.internal |
| 2  | jsmith   | john.smith@testcorp.internal |
</pre></body></html>""")
        resp = add_standard_headers(resp)
        return resp

    resp = make_response("""<html><body>
    <h2>SQL Console</h2>
    <form method="POST">
        <textarea name="query" rows="5" cols="80">SELECT * FROM users LIMIT 10;</textarea><br>
        <button>Execute</button>
    </form>
    </body></html>""")
    resp = add_standard_headers(resp)
    return resp


@app.route("/admin/stats")
def admin_stats():
    period = request.args.get("period", "7d")
    metric = request.args.get("metric", "users")
    resp = jsonify({"period": period, "metric": metric,
                    "data": [100, 120, 95, 140, 160, 130, 110]})
    return resp


# ---------------------------------------------------------------------------
# Site 4: Upload / file handling
# ---------------------------------------------------------------------------

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        resp = jsonify({"status": "uploaded", "path": "/uploads/user_file.pdf"})
        return resp

    resp = make_response("""<html><body>
    <h2>File Upload</h2>
    <form method="POST" action="/upload" enctype="multipart/form-data">
        <input type="file" name="file">
        <input type="hidden" name="upload_dir" value="/var/www/uploads">
        <select name="category">
            <option value="documents">Documents</option>
            <option value="images">Images</option>
        </select>
        <button>Upload</button>
    </form>
    <form method="POST" action="/api/v1/import">
        <label>Import CSV: <input type="file" name="csv_file"></label>
        <input type="hidden" name="table" value="products">
        <input type="hidden" name="delimiter" value=",">
        <button>Import</button>
    </form>
    </body></html>""")
    resp = add_standard_headers(resp)
    return resp


@app.route("/api/v1/import", methods=["POST"])
def api_import():
    table = request.form.get("table", "")
    resp = jsonify({"status": "imported", "table": table, "rows": 42})
    return resp


# ---------------------------------------------------------------------------
# Site 5: Secure section (proper headers)
# ---------------------------------------------------------------------------

@app.route("/secure/profile")
def secure_profile():
    user_id = request.args.get("id", "1")
    resp = make_response(f"""<html><body>
    <h2>User Profile</h2>
    <p>User ID: {user_id}</p>
    <form method="POST" action="/secure/profile/update">
        <input type="hidden" name="user_id" value="{user_id}">
        <label>Display Name: <input type="text" name="display_name" value="John Smith"></label><br>
        <label>Bio: <textarea name="bio">Software Engineer</textarea></label><br>
        <button>Update</button>
    </form>
    </body></html>""")
    resp = add_standard_headers(resp)
    resp = add_secure_headers(resp)
    return resp


@app.route("/secure/profile/update", methods=["POST"])
def secure_profile_update():
    blocked = waf_check()
    if blocked:
        return blocked
    resp = make_response(redirect("/secure/profile"))
    return resp


# ---------------------------------------------------------------------------
# JS files (for JS analyzer)
# ---------------------------------------------------------------------------

@app.route("/static/js/app.js")
def js_app():
    resp = make_response("""
// TestCorp Frontend Application
var e="/api/v1/users",t="/api/v1/orders",n="/api/v1/products";

function loadDashboard() {
    fetch("/api/v1/dashboard/stats?period=30d&metric=revenue")
        .then(r => r.json())
        .then(data => renderChart(data));

    $.getJSON("/api/v1/notifications?unread=true&limit=10");
}

function updateProfile(userId) {
    axios.put(`/api/v1/users/${userId}`, {
        display_name: document.getElementById('name').value,
        email: document.getElementById('email').value,
        preferences: {theme: 'dark', language: 'en'}
    });
}

function deleteAccount(userId) {
    axios.delete(`/api/v1/users/${userId}`);
}

// Admin functions
function exportData(table, format) {
    fetch(`/admin/export?table=${table}&format=${format}&columns=*`);
}

// Search with filters
function advancedSearch(query, filters) {
    const params = new URLSearchParams();
    params.append("q", query);
    params.append("category", filters.category);
    params.append("min_price", filters.minPrice);
    params.append("max_price", filters.maxPrice);
    params.append("in_stock", filters.inStock);
    fetch(`/api/v1/search?${params}`);
}

// Batch operations
axios.post("/api/v1/batch/process", {
    operation: "update_prices",
    product_ids: [1, 2, 3],
    modifier: 1.1,
    apply_to: "category"
});

// Coupon/voucher validation
fetch("/api/v1/vouchers/validate", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
        code: "SUMMER2024",
        cart_total: 99.99,
        user_id: 42
    })
});
""")
    resp.headers["Content-Type"] = "application/javascript"
    return resp


@app.route("/static/js/api-client.js")
def js_api_client():
    resp = make_response("""
// API Client Library
const BASE_URL = "/api/v1";
const INTERNAL_API = "http://10.0.1.50:8443/internal";

class APIClient {
    constructor(token) {
        this.token = token;
        this.baseUrl = BASE_URL;
    }

    async getUser(id) {
        return this.request(`/api/v1/users/${id}`);
    }

    async updateUser(id, data) {
        return fetch(`/api/v1/users/${id}`, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + this.token
            },
            body: JSON.stringify({
                username: data.username,
                email: data.email,
                role: data.role,
                department: data.department,
                manager_id: data.managerId
            })
        });
    }

    async createOrder(items) {
        return axios.post("/api/v1/orders", {
            items: items,
            shipping_address: "default",
            payment_method: "card",
            coupon_code: "",
            notes: ""
        });
    }

    async searchProducts(query) {
        const p = new URLSearchParams();
        p.set("query", query.text);
        p.set("brand", query.brand);
        p.set("min_rating", query.minRating);
        p.set("page_size", query.pageSize);
        return fetch(`/api/v1/products/search?${p}`);
    }

    async getReport(params) {
        return fetch(`/api/v1/reports?type=${params.type}&date_from=${params.from}&date_to=${params.to}&group_by=${params.groupBy}`);
    }
}

// Payment processing
function processPayment(paymentData) {
    return axios.post("/api/v1/payments/charge", {
        amount: paymentData.amount,
        currency: "USD",
        card_token: paymentData.token,
        order_id: paymentData.orderId,
        billing_email: paymentData.email
    });
}

// Password reset
function resetPassword(email) {
    return fetch("/api/v1/auth/reset-password", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({email: email, callback_url: "/reset-confirm"})
    });
}

// File operations
function downloadFile(fileId) {
    window.location = `/api/v1/files/${fileId}/download?token=temp_token_123`;
}
""")
    resp.headers["Content-Type"] = "application/javascript"
    return resp


# Additional API endpoints discovered via JS
@app.route("/api/v1/search")
@app.route("/api/v1/products/search")
def api_search():
    resp = jsonify({"results": [], "total": 0})
    return resp


@app.route("/api/v1/dashboard/stats")
def api_dashboard_stats():
    resp = jsonify({"revenue": 125000, "users": 342, "orders": 89})
    return resp


@app.route("/api/v1/notifications")
def api_notifications():
    resp = jsonify({"notifications": [], "unread": 0})
    return resp


@app.route("/api/v1/batch/process", methods=["POST"])
def api_batch():
    resp = jsonify({"status": "queued", "job_id": "batch_001"})
    return resp


@app.route("/api/v1/vouchers/validate", methods=["POST"])
def api_voucher():
    data = request.json or {}
    code = data.get("code", "")
    # Predictable voucher validation
    valid_codes = {"SUMMER2024": 10, "WELCOME10": 10, "VIP50": 50}
    if code in valid_codes:
        resp = jsonify({"valid": True, "discount_percent": valid_codes[code],
                        "code": code})
    else:
        resp = jsonify({"valid": False, "message": "Invalid voucher code"})
    return resp


@app.route("/api/v1/payments/charge", methods=["POST"])
def api_payment():
    resp = jsonify({"status": "charged", "transaction_id": "txn_abc123"})
    return resp


@app.route("/api/v1/auth/reset-password", methods=["POST"])
def api_reset_password():
    resp = jsonify({"status": "sent"})
    return resp


@app.route("/api/v1/files/<file_id>/download")
def api_file_download(file_id):
    token = request.args.get("token", "")
    resp = make_response(f"File content for {file_id}")
    resp.headers["Content-Type"] = "application/octet-stream"
    return resp


# ---------------------------------------------------------------------------
# robots.txt and sitemap
# ---------------------------------------------------------------------------

@app.route("/robots.txt")
def robots():
    resp = make_response("""User-agent: *
Disallow: /admin/
Disallow: /api/internal/
Disallow: /backup/
Allow: /api/v1/

Sitemap: http://localhost:5199/sitemap.xml
""")
    resp.headers["Content-Type"] = "text/plain"
    return resp


@app.route("/sitemap.xml")
def sitemap():
    resp = make_response("""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url><loc>http://localhost:5199/</loc></url>
    <url><loc>http://localhost:5199/products</loc></url>
    <url><loc>http://localhost:5199/search</loc></url>
    <url><loc>http://localhost:5199/login</loc></url>
    <url><loc>http://localhost:5199/api/v1/docs</loc></url>
</urlset>""")
    resp.headers["Content-Type"] = "application/xml"
    return resp


# ---------------------------------------------------------------------------
# .env file (exposed)
# ---------------------------------------------------------------------------

@app.route("/.env")
def dotenv():
    resp = make_response("""# TestCorp Production Config — DO NOT COMMIT
DATABASE_URL=postgres://app_user:s3cretP4ss@db-prod-01.testcorp.internal:5432/testcorp_prod
REDIS_URL=redis://cache-01.testcorp.internal:6379/0
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_test_FAKE_KEY_FOR_TESTING_ONLY
JWT_SECRET=super_secret_jwt_key_do_not_share
SENTRY_DSN=https://abc123@sentry.testcorp.internal/5
SMTP_PASSWORD=mailpass123
ADMIN_API_KEY=ak_prod_9f8e7d6c5b4a3210
""")
    resp.headers["Content-Type"] = "text/plain"
    return resp


# ---------------------------------------------------------------------------
# WAF stats endpoint (for test verification)
# ---------------------------------------------------------------------------

@app.route("/_test/stats")
def test_stats():
    return jsonify({
        "waf_blocks": WAF_BLOCK_COUNT,
        "waf_log": WAF_REQUEST_LOG[-20:],
    })


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5199
    print(f"\n  Test sites running on http://localhost:{port}")
    print(f"  WAF stats: http://localhost:{port}/_test/stats")
    print(f"  Press Ctrl+C to stop\n")
    app.run(host="127.0.0.1", port=port, debug=False)
