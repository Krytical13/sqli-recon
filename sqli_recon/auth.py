"""Authentication — auto-login, CSRF handling, session health monitoring."""

import re
import logging
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

log = logging.getLogger(__name__)


class SessionManager:
    """
    Manages authenticated sessions throughout a scan.

    - Auto-detects login forms
    - Extracts and submits CSRF tokens
    - Monitors session health (detects expiry/redirect to login)
    - Re-authenticates automatically when session dies
    """

    def __init__(self, client, target_url, credentials=None):
        """
        Args:
            client: HttpClient instance
            target_url: Base target URL
            credentials: Dict with 'username' and 'password', or None for cookie-only auth
        """
        self.client = client
        self.target_url = target_url
        self.credentials = credentials
        self.login_url = None
        self.login_form = None  # Parsed form details
        self._auth_cookies = {}
        self._login_attempts = 0
        self._max_login_attempts = 3
        self._logged_in = False

    def auto_login(self):
        """Find the login form and authenticate. Returns True on success."""
        if not self.credentials:
            return False

        # Find login page
        self.login_url = self._find_login_page()
        if not self.login_url:
            log.warning("Could not find login page")
            return False

        # Parse the login form
        self.login_form = self._parse_login_form(self.login_url)
        if not self.login_form:
            log.warning(f"Could not parse login form at {self.login_url}")
            return False

        # Submit credentials
        return self._submit_login()

    def check_session(self, resp):
        """
        Check if a response indicates an expired/invalid session.
        Returns True if session is still valid.
        """
        if resp is None:
            return True  # Network error, not a session issue

        # Redirect to login page
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            if self._is_login_url(location):
                return False

        # Check if response body is actually a login page
        if resp.status_code == 200 and resp.text:
            body = resp.text[:3000].lower()
            if self._looks_like_login_page(body) and self.login_url:
                # Only flag if we're NOT requesting the login page itself
                if self.login_url not in resp.url:
                    return False

        return True

    def ensure_session(self, resp):
        """
        Check session health and re-login if needed.
        Returns True if session is (now) valid.
        """
        if self.check_session(resp):
            return True

        if not self.credentials:
            return False

        log.info("Session expired, re-authenticating...")
        if self._login_attempts >= self._max_login_attempts:
            log.warning("Max login attempts reached, giving up re-auth")
            return False

        return self._submit_login()

    def _find_login_page(self):
        """Try common login page paths and return the first one that has a form."""
        parsed = urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Common login paths across platforms
        login_paths = [
            "/login", "/signin", "/auth/login", "/user/login",
            "/account/login", "/member.php?action=login",
            "/wp-login.php", "/admin/login", "/ucp.php?mode=login",
            "/index.php?action=login", "/login.php", "/login.aspx",
            "/login.jsp", "/users/sign_in",
        ]

        # First check if the main page redirects to login
        resp = self.client.get(self.target_url, allow_redirects=False)
        if resp and resp.status_code in (301, 302, 303, 307):
            location = resp.headers.get("Location", "")
            if self._is_login_url(location):
                return urljoin(self.target_url, location)

        # Try common paths
        for path in login_paths:
            url = base + path
            resp = self.client.get(url)
            if resp and resp.status_code == 200:
                if self._has_login_form(resp.text):
                    log.info(f"Found login form at {url}")
                    return url

        return None

    def _parse_login_form(self, login_url):
        """Parse a login page to extract form details including CSRF tokens."""
        resp = self.client.get(login_url)
        if resp is None or resp.status_code != 200:
            return None

        try:
            soup = BeautifulSoup(resp.text, "lxml")
        except Exception:
            soup = BeautifulSoup(resp.text, "html.parser")

        # Find the login form (form with password field)
        for form in soup.find_all("form"):
            has_password = form.find("input", {"type": "password"})
            if not has_password:
                continue

            action = form.get("action", "")
            method = form.get("method", "POST").upper()
            action_url = urljoin(login_url, action) if action else login_url

            # Extract all fields
            fields = {}
            username_field = None
            password_field = None

            for inp in form.find_all(["input", "select", "textarea"]):
                name = inp.get("name")
                if not name:
                    continue

                input_type = inp.get("type", "text").lower()
                value = inp.get("value", "")

                if input_type == "password":
                    password_field = name
                    fields[name] = ""  # Will be filled with credential
                elif input_type in ("text", "email") and username_field is None:
                    username_field = name
                    fields[name] = ""  # Will be filled with credential
                elif input_type == "hidden":
                    # Hidden fields include CSRF tokens, action fields, etc.
                    fields[name] = value
                elif input_type == "submit":
                    if value:
                        fields[name] = value
                elif input_type == "checkbox":
                    # Remember me / stay logged in — check it
                    fields[name] = value or "on"
                else:
                    fields[name] = value

            if not username_field or not password_field:
                continue

            return {
                "action_url": action_url,
                "method": method,
                "fields": fields,
                "username_field": username_field,
                "password_field": password_field,
            }

        return None

    def _submit_login(self):
        """Submit the login form with credentials."""
        if not self.login_form or not self.credentials:
            return False

        self._login_attempts += 1
        form = self.login_form

        # Re-fetch the login page to get fresh CSRF token
        if self._login_attempts > 1:
            fresh_form = self._parse_login_form(self.login_url)
            if fresh_form:
                form = fresh_form
                self.login_form = form

        # Fill in credentials
        data = dict(form["fields"])
        data[form["username_field"]] = self.credentials["username"]
        data[form["password_field"]] = self.credentials["password"]

        log.info(f"Submitting login to {form['action_url']} "
                 f"(user field: {form['username_field']}, "
                 f"pass field: {form['password_field']}, "
                 f"hidden fields: {len(form['fields']) - 2})")

        # Submit
        resp = self.client.post(form["action_url"], data=data, allow_redirects=True)
        if resp is None:
            return False

        # Check if login succeeded:
        # 1. We got redirected away from the login page
        # 2. The response doesn't contain a login form anymore
        # 3. New cookies were set
        success = False

        if resp.url and not self._is_login_url(resp.url):
            success = True
        elif resp.status_code == 200 and not self._has_login_form(resp.text):
            success = True

        # Check for new session cookies
        new_cookies = self.client.session.cookies.get_dict()
        if len(new_cookies) > len(self._auth_cookies):
            success = True

        if success:
            self._auth_cookies = new_cookies
            self._logged_in = True
            log.info("Login successful")
            return True

        # Check for common error indicators
        if resp.text:
            body_lower = resp.text[:2000].lower()
            if any(s in body_lower for s in [
                "invalid", "incorrect", "wrong password", "login failed",
                "bad credentials", "authentication failed",
            ]):
                log.warning("Login failed — invalid credentials")
            else:
                log.warning("Login may have failed — could not confirm success")

        return False

    def _has_login_form(self, html):
        """Check if HTML contains a login form (form with password input)."""
        if not html:
            return False
        return bool(re.search(
            r'<form[^>]*>.*?<input[^>]*type=["\']password["\']',
            html[:5000], re.I | re.DOTALL,
        ))

    def _looks_like_login_page(self, body):
        """Heuristic check if response body looks like a login page."""
        indicators = ["login", "sign in", "log in", "username", "password",
                       "authenticate", "credentials"]
        hits = sum(1 for s in indicators if s in body)
        return hits >= 3

    def _is_login_url(self, url):
        """Check if a URL looks like a login page."""
        url_lower = url.lower()
        return any(s in url_lower for s in [
            "login", "signin", "sign_in", "auth",
            "ucp.php?mode=login", "wp-login",
            "action=login", "member.php?action=login",
        ])

    @property
    def is_authenticated(self):
        return self._logged_in
