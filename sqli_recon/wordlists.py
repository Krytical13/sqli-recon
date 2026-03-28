"""Embedded wordlists for parameter discovery and API path brute-forcing."""

# Parameter names commonly involved in SQL queries.
# Organized by risk category for the classifier.

SQLI_HIGH_RISK_PARAMS = [
    # Direct ID lookups (WHERE id = X)
    "id", "Id", "ID", "uid", "pid", "cid", "nid", "sid", "tid", "rid",
    "user_id", "userId", "item_id", "itemId", "product_id", "productId",
    "order_id", "orderId", "cat_id", "catId", "category_id", "categoryId",
    "post_id", "postId", "comment_id", "commentId", "page_id", "pageId",
    "article_id", "articleId", "file_id", "fileId", "doc_id", "docId",
    "group_id", "groupId", "account_id", "accountId", "invoice_id",
    "customer_id", "customerId", "session_id", "sessionId", "transaction_id",
    "msg_id", "msgId", "thread_id", "threadId", "parent_id", "parentId",
    "ref", "ref_id", "refId", "record_id", "recordId", "entry_id",

    # Search / text input that hits queries
    "q", "query", "search", "keyword", "term", "s", "find", "lookup",
    "search_query", "searchQuery", "search_term", "searchTerm",
    "keywords", "text", "input",

    # Sort / order (ORDER BY injection)
    "sort", "order", "orderby", "order_by", "sortby", "sort_by",
    "sortfield", "sortField", "sort_field", "orderfield", "orderField",
    "dir", "direction", "asc", "desc", "sort_dir", "sortDir",
    "sort_order", "sortOrder", "sort_column", "sortColumn",

    # Filter / where clauses
    "filter", "where", "column", "col", "field", "table", "type",
    "group", "groupby", "group_by", "having", "condition", "criteria",
    "status", "state", "category", "cat", "tag", "label",
]

SQLI_MEDIUM_RISK_PARAMS = [
    # Pagination / range (LIMIT, OFFSET)
    "limit", "offset", "page", "per_page", "perPage", "page_size",
    "pageSize", "count", "num", "from", "to", "start", "end",
    "skip", "take", "first", "last", "after", "before",
    "min", "max", "range", "between",

    # Auth / user data (login queries)
    "username", "user", "uname", "login", "email", "mail",
    "password", "pass", "passwd", "pwd",
    "name", "fname", "lname", "first_name", "last_name",
    "firstname", "lastname",

    # Content / data fields
    "title", "subject", "description", "desc", "content", "body",
    "message", "msg", "comment", "note", "review", "feedback",
    "address", "city", "country", "region", "zip", "postal",
    "phone", "tel", "mobile",

    # Date / time (date-based queries)
    "date", "year", "month", "day", "time", "timestamp",
    "created", "updated", "modified", "since", "until",
    "start_date", "startDate", "end_date", "endDate",
    "from_date", "fromDate", "to_date", "toDate",
    "date_from", "date_to", "created_at", "updated_at",

    # Numeric values
    "price", "amount", "total", "qty", "quantity", "cost",
    "rate", "score", "rating", "weight", "size", "width", "height",
    "age", "year", "number", "no", "code",

    # Identifiers (string-based lookups)
    "slug", "handle", "key", "token", "uuid", "guid", "hash",
    "sku", "barcode", "serial", "model", "version",
]

SQLI_LOW_RISK_PARAMS = [
    # Display / formatting (rarely SQL, but possible)
    "format", "output", "view", "mode", "layout", "template",
    "theme", "style", "display", "render", "show",
    "lang", "language", "locale", "currency", "timezone", "tz",
    "callback", "jsonp", "redirect", "return", "next", "goto",
    "dest", "destination", "url", "link", "path",
    "action", "do", "cmd", "op", "operation", "method",
    "tab", "section", "panel", "step", "phase",
    "debug", "test", "verbose", "raw", "preview", "draft",
    "enabled", "active", "visible", "published", "deleted", "archived",
    "role", "permission", "access", "level", "admin", "auth",
    "source", "src", "origin", "channel", "medium", "campaign",
    "utm_source", "utm_medium", "utm_campaign",
]

# All params combined for fuzzing
ALL_PARAMS = SQLI_HIGH_RISK_PARAMS + SQLI_MEDIUM_RISK_PARAMS + SQLI_LOW_RISK_PARAMS

# Common API base paths to brute-force
API_PATHS = [
    # Versioned API roots
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/rest", "/rest/v1", "/rest/v2",

    # Common REST resources
    "/api/users", "/api/user", "/api/accounts", "/api/account",
    "/api/products", "/api/product", "/api/items", "/api/item",
    "/api/orders", "/api/order", "/api/posts", "/api/post",
    "/api/comments", "/api/comment", "/api/categories", "/api/category",
    "/api/tags", "/api/search", "/api/auth", "/api/login",
    "/api/register", "/api/logout", "/api/profile", "/api/settings",
    "/api/config", "/api/status", "/api/health", "/api/info",
    "/api/data", "/api/export", "/api/import", "/api/upload",
    "/api/download", "/api/files", "/api/images", "/api/media",
    "/api/messages", "/api/notifications", "/api/events", "/api/logs",
    "/api/reports", "/api/stats", "/api/analytics", "/api/dashboard",
    "/api/payments", "/api/invoices", "/api/transactions",
    "/api/customers", "/api/contacts", "/api/leads",

    # Versioned resources
    "/api/v1/users", "/api/v1/products", "/api/v1/orders",
    "/api/v1/search", "/api/v1/auth", "/api/v1/login",
    "/api/v2/users", "/api/v2/products", "/api/v2/orders",

    # GraphQL
    "/graphql", "/graphiql", "/api/graphql", "/gql",
    "/playground", "/altair", "/voyager",

    # Documentation / schema (reveals all endpoints)
    "/swagger.json", "/swagger.yaml", "/swagger/",
    "/openapi.json", "/openapi.yaml", "/openapi/",
    "/api-docs", "/api-docs.json", "/api/docs",
    "/docs", "/redoc", "/api/schema",
    "/api/swagger", "/api/openapi",
    "/.well-known/openapi.json",
    "/api/v1/swagger.json", "/api/v2/swagger.json",

    # Admin / internal
    "/admin", "/admin/api", "/internal", "/internal/api",
    "/debug", "/debug/api", "/management", "/actuator",

    # Common frameworks
    "/wp-json/wp/v2",  # WordPress
    "/jsonapi",  # Drupal
    "/index.php/rest",  # Magento
    "/_api",  # Wix
]

# HTTP methods to try for discovered API endpoints
API_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]
