"""
Intentionally vulnerable Flask app for testing sqli_recon.

- Binds to 127.0.0.1:18484 ONLY (no external exposure)
- Uses in-memory SQLite (nothing persisted)
- Exercises every feature sqli_recon should detect:
    - Query parameters, form fields, path parameters
    - REST API with JSON bodies
    - JavaScript files with embedded API endpoints
    - Search, sort, filter, pagination, login
    - robots.txt, sitemap.xml
    - HTML comments with hidden endpoints
"""

import sqlite3
import json
from flask import Flask, request, jsonify, Response, g

app = Flask(__name__)
PORT = 18484
HOST = "127.0.0.1"


# ---- In-memory SQLite setup ----

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(":memory:")
        g.db.row_factory = sqlite3.Row
        _init_db(g.db)
    return g.db


def _init_db(db):
    db.executescript("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY, username TEXT, email TEXT, role TEXT
        );
        CREATE TABLE products (
            id INTEGER PRIMARY KEY, name TEXT, category TEXT, price REAL, description TEXT
        );
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY, user_id INTEGER, product_id INTEGER, quantity INTEGER, status TEXT
        );
        INSERT INTO users VALUES (1, 'admin', 'admin@test.local', 'admin');
        INSERT INTO users VALUES (2, 'alice', 'alice@test.local', 'user');
        INSERT INTO users VALUES (3, 'bob', 'bob@test.local', 'user');
        INSERT INTO products VALUES (1, 'Widget A', 'gadgets', 29.99, 'A fine widget');
        INSERT INTO products VALUES (2, 'Widget B', 'gadgets', 49.99, 'A better widget');
        INSERT INTO products VALUES (3, 'Gizmo X', 'tools', 19.99, 'Handy gizmo');
        INSERT INTO products VALUES (4, 'Gizmo Y', 'tools', 39.99, 'Premium gizmo');
        INSERT INTO products VALUES (5, 'Doohickey', 'misc', 9.99, 'What is it?');
        INSERT INTO orders VALUES (1, 1, 1, 2, 'shipped');
        INSERT INTO orders VALUES (2, 2, 3, 1, 'pending');
        INSERT INTO orders VALUES (3, 3, 2, 5, 'delivered');
    """)


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---- HTML pages (crawlable) ----

@app.route("/")
def index():
    return """<!DOCTYPE html>
<html>
<head><title>Test Shop</title>
<script src="/static/js/app.js"></script>
<script src="/static/js/api-client.js"></script>
</head>
<body>
<h1>Test Shop</h1>
<nav>
  <a href="/products">Products</a>
  <a href="/products?category=gadgets">Gadgets</a>
  <a href="/products?category=tools">Tools</a>
  <a href="/search">Search</a>
  <a href="/login">Login</a>
  <a href="/orders">Orders</a>
  <a href="/admin/dashboard">Admin</a>
</nav>
<!-- TODO: add /api/v2/inventory endpoint -->
<!-- Debug: /internal/debug?verbose=true -->
<script>
  var apiBase = "/api/v1";
  fetch("/api/v1/products?limit=5").then(r => r.json());
</script>
</body>
</html>"""


@app.route("/products")
def products_page():
    db = get_db()
    category = request.args.get("category", "")
    sort = request.args.get("sort", "name")
    order = request.args.get("order", "asc")
    page = request.args.get("page", "1")
    per_page = request.args.get("per_page", "10")

    # Intentionally vulnerable: string formatting in ORDER BY
    query = "SELECT * FROM products"
    if category:
        query += f" WHERE category = '{category}'"
    query += f" ORDER BY {sort} {order}"

    try:
        rows = db.execute(query).fetchall()
    except Exception as e:
        return f"<h1>Database Error</h1><pre>{e}</pre>", 500

    html = "<html><head><title>Products</title></head><body>"
    html += "<h1>Products</h1>"
    html += f'<a href="/products?category=gadgets&sort=price&order=asc">Gadgets by price</a><br>'
    html += f'<a href="/products?category=tools&sort=name&order=desc">Tools by name</a><br>'
    html += "<table><tr><th>ID</th><th>Name</th><th>Category</th><th>Price</th></tr>"
    for row in rows:
        html += f'<tr><td><a href="/products/{row["id"]}">{row["id"]}</a></td>'
        html += f'<td>{row["name"]}</td><td>{row["category"]}</td><td>${row["price"]}</td></tr>'
    html += "</table></body></html>"
    return html


@app.route("/products/<int:product_id>")
def product_detail(product_id):
    db = get_db()
    # Intentionally vulnerable
    row = db.execute(f"SELECT * FROM products WHERE id = {product_id}").fetchone()
    if not row:
        return "Not found", 404
    return f"""<html><body>
    <h1>{row['name']}</h1>
    <p>Category: {row['category']}</p>
    <p>Price: ${row['price']}</p>
    <p>{row['description']}</p>
    <a href="/products">Back</a>
    </body></html>"""


@app.route("/search")
def search_page():
    db = get_db()
    q = request.args.get("q", "")
    results = []
    if q:
        # Intentionally vulnerable
        try:
            results = db.execute(
                f"SELECT * FROM products WHERE name LIKE '%{q}%' OR description LIKE '%{q}%'"
            ).fetchall()
        except Exception as e:
            return f"<h1>Error</h1><pre>{e}</pre>", 500

    return f"""<html><body>
    <h1>Search Products</h1>
    <form method="GET" action="/search">
        <input type="text" name="q" value="{q}" placeholder="Search...">
        <select name="search_in">
            <option value="all">All fields</option>
            <option value="name">Name only</option>
            <option value="description">Description only</option>
        </select>
        <button type="submit">Search</button>
    </form>
    <p>{len(results)} results</p>
    {''.join(f'<div><a href="/products/{r["id"]}">{r["name"]}</a> - ${r["price"]}</div>' for r in results)}
    </body></html>"""


@app.route("/login", methods=["GET", "POST"])
def login_page():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        # Intentionally vulnerable
        try:
            row = db.execute(
                f"SELECT * FROM users WHERE username = '{username}' AND role = 'admin'"
            ).fetchone()
            if row:
                error = "Login simulated (vulnerable app)"
            else:
                error = "Invalid credentials"
        except Exception as e:
            error = f"Error: {e}"

    return f"""<html><body>
    <h1>Login</h1>
    <p style="color:red">{error}</p>
    <form method="POST" action="/login">
        <input type="text" name="username" placeholder="Username"><br>
        <input type="password" name="password" placeholder="Password"><br>
        <input type="hidden" name="redirect" value="/admin/dashboard">
        <button type="submit">Login</button>
    </form>
    </body></html>"""


@app.route("/orders")
def orders_page():
    user_id = request.args.get("user_id", "")
    status = request.args.get("status", "")
    sort_by = request.args.get("sort_by", "id")

    db = get_db()
    query = "SELECT * FROM orders"
    conditions = []
    if user_id:
        conditions.append(f"user_id = {user_id}")
    if status:
        conditions.append(f"status = '{status}'")
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += f" ORDER BY {sort_by}"

    try:
        rows = db.execute(query).fetchall()
    except Exception as e:
        return f"<h1>Error</h1><pre>{e}</pre>", 500

    html = "<html><body><h1>Orders</h1>"
    html += '<a href="/orders?user_id=1&status=shipped&sort_by=quantity">User 1 shipped</a><br>'
    html += "<table><tr><th>ID</th><th>User</th><th>Product</th><th>Qty</th><th>Status</th></tr>"
    for row in rows:
        html += f'<tr><td>{row["id"]}</td><td>{row["user_id"]}</td>'
        html += f'<td>{row["product_id"]}</td><td>{row["quantity"]}</td><td>{row["status"]}</td></tr>'
    html += "</table></body></html>"
    return html


@app.route("/admin/dashboard")
def admin_dashboard():
    return """<html><body>
    <h1>Admin Dashboard</h1>
    <a href="/admin/users">Manage Users</a><br>
    <a href="/admin/users?role=admin">Admin Users</a><br>
    <a href="/api/v1/stats?range=30d">API Stats</a><br>
    <script>
        // Admin API calls
        fetch("/api/v1/users?role=admin&limit=50");
        axios.post("/api/v1/reports", {"type": "sales", "date_from": "2024-01-01"});
    </script>
    </body></html>"""


@app.route("/admin/users")
def admin_users():
    db = get_db()
    role = request.args.get("role", "")
    query = "SELECT * FROM users"
    if role:
        query += f" WHERE role = '{role}'"
    rows = db.execute(query).fetchall()
    html = "<html><body><h1>Users</h1><ul>"
    for row in rows:
        html += f'<li><a href="/api/v1/users/{row["id"]}">{row["username"]}</a> ({row["role"]})</li>'
    html += "</ul></body></html>"
    return html


# ---- REST API ----

@app.route("/api/v1/products", methods=["GET"])
def api_products():
    db = get_db()
    category = request.args.get("category", "")
    sort = request.args.get("sort", "id")
    limit = request.args.get("limit", "20")
    offset = request.args.get("offset", "0")
    min_price = request.args.get("min_price", "")
    max_price = request.args.get("max_price", "")

    query = "SELECT * FROM products"
    conditions = []
    if category:
        conditions.append(f"category = '{category}'")
    if min_price:
        conditions.append(f"price >= {min_price}")
    if max_price:
        conditions.append(f"price <= {max_price}")
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += f" ORDER BY {sort} LIMIT {limit} OFFSET {offset}"

    try:
        rows = db.execute(query).fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/products/<int:product_id>")
def api_product_detail(product_id):
    db = get_db()
    row = db.execute(f"SELECT * FROM products WHERE id = {product_id}").fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


@app.route("/api/v1/users", methods=["GET"])
def api_users():
    db = get_db()
    role = request.args.get("role", "")
    limit = request.args.get("limit", "20")
    query = "SELECT id, username, email, role FROM users"
    if role:
        query += f" WHERE role = '{role}'"
    query += f" LIMIT {limit}"
    rows = db.execute(query).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/v1/users/<int:user_id>")
def api_user_detail(user_id):
    db = get_db()
    row = db.execute(f"SELECT id, username, email, role FROM users WHERE id = {user_id}").fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


@app.route("/api/v1/search", methods=["POST"])
def api_search():
    data = request.get_json(silent=True) or {}
    query_text = data.get("query", "")
    field = data.get("field", "name")
    limit = data.get("limit", 10)

    db = get_db()
    try:
        rows = db.execute(
            f"SELECT * FROM products WHERE {field} LIKE '%{query_text}%' LIMIT {limit}"
        ).fetchall()
        return jsonify({"results": [dict(r) for r in rows]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/orders", methods=["GET"])
def api_orders():
    db = get_db()
    user_id = request.args.get("user_id", "")
    status = request.args.get("status", "")
    sort = request.args.get("sort", "id")

    query = "SELECT * FROM orders"
    conditions = []
    if user_id:
        conditions.append(f"user_id = {user_id}")
    if status:
        conditions.append(f"status = '{status}'")
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += f" ORDER BY {sort}"

    try:
        rows = db.execute(query).fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/stats")
def api_stats():
    r = request.args.get("range", "7d")
    return jsonify({"range": r, "visits": 1234, "orders": 56})


@app.route("/api/v1/reports", methods=["POST"])
def api_reports():
    data = request.get_json(silent=True) or {}
    return jsonify({"status": "generated", "type": data.get("type", "unknown")})


@app.route("/internal/debug")
def internal_debug():
    verbose = request.args.get("verbose", "false")
    return jsonify({"debug": True, "verbose": verbose, "db": "sqlite::memory:"})


# ---- Static JS files ----

@app.route("/static/js/app.js")
def js_app():
    return Response("""
// Main application
const API_BASE = "/api/v1";

function loadProducts(category, page) {
    fetch(API_BASE + "/products?category=" + category + "&page=" + page + "&per_page=20")
        .then(r => r.json())
        .then(data => renderProducts(data));
}

function searchProducts(term) {
    fetch("/api/v1/search", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({query: term, field: "name", limit: 50})
    }).then(r => r.json());
}

function loadUser(userId) {
    fetch("/api/v1/users/" + userId).then(r => r.json());
}

function loadOrders(userId, status) {
    fetch(`/api/v1/orders?user_id=${userId}&status=${status}&sort=id`)
        .then(r => r.json());
}

// Route config
const routes = [
    {path: "/products/:id", component: "ProductDetail"},
    {path: "/users/:id/orders", component: "UserOrders"},
    {path: "/categories/:slug/items", component: "CategoryItems"},
    {path: "/reports/:type", component: "ReportView"},
];
""", mimetype="application/javascript")


@app.route("/static/js/api-client.js")
def js_api_client():
    return Response("""
// API client module
class ApiClient {
    constructor() {
        this.baseUrl = "/api/v1";
    }

    getProduct(id) {
        return axios.get(this.baseUrl + "/products/" + id);
    }

    deleteProduct(id) {
        return axios.delete("/api/v1/products/" + id);
    }

    updateUser(id, data) {
        return axios.put("/api/v1/users/" + id, data);
    }

    getReport(params) {
        return $.getJSON("/api/v1/reports?type=" + params.type + "&date_from=" + params.dateFrom);
    }

    exportData(format) {
        return fetch("/api/v1/export?format=" + format + "&table=products");
    }

    adminSearch(query) {
        var params = new URLSearchParams();
        params.set("q", query);
        params.set("scope", "all");
        return fetch("/admin/api/search?" + params.toString());
    }

    bulkOperation(action, ids) {
        return fetch("/api/v1/bulk", {
            method: "POST",
            body: JSON.stringify({action: action, ids: ids, confirm: true})
        });
    }
}

// Hidden admin endpoints
// POST /api/v1/admin/sql-console  (internal use only)
// GET /api/v1/admin/export?table=users&format=csv
""", mimetype="application/javascript")


# ---- robots.txt & sitemap ----

@app.route("/robots.txt")
def robots():
    host = request.host
    return Response(f"""User-agent: *
Allow: /products
Allow: /search
Disallow: /admin/
Disallow: /internal/
Disallow: /api/v1/admin/
Sitemap: http://{host}/sitemap.xml
""", mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap():
    host = request.host
    return Response(f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://{host}/</loc></url>
  <url><loc>http://{host}/products</loc></url>
  <url><loc>http://{host}/products?category=gadgets</loc></url>
  <url><loc>http://{host}/products?category=tools</loc></url>
  <url><loc>http://{host}/search</loc></url>
  <url><loc>http://{host}/products/1</loc></url>
  <url><loc>http://{host}/products/2</loc></url>
  <url><loc>http://{host}/products/3</loc></url>
</urlset>""", mimetype="application/xml")


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--waf", action="store_true", help="Enable WAF + rate limiting")
    p.add_argument("--rpm", type=int, default=40, help="Rate limit: requests per minute (default: 40)")
    p.add_argument("--burst", type=int, default=10, help="Rate limit: burst allowance (default: 10)")
    args = p.parse_args()

    if args.waf:
        from waf import register_waf
        stats = register_waf(app, requests_per_minute=args.rpm, burst=args.burst)
        print(f"WAF enabled: rate_limit={args.rpm}rpm, burst={args.burst}")

    print(f"Starting vulnerable test app on {HOST}:{PORT}")
    print(f"ONLY accessible from localhost - not exposed externally")
    app.run(host=HOST, port=PORT, debug=False)
