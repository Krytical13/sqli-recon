"""DVWA-specific session bootstrap: DB setup + login + set security=low."""
import logging
import time

from bs4 import BeautifulSoup

log = logging.getLogger(__name__)


def _get_token(resp_text: str) -> str:
    """Extract user_token CSRF value from an HTML response."""
    soup = BeautifulSoup(resp_text, "html.parser")
    token_input = soup.find("input", {"name": "user_token"})
    return token_input["value"] if token_input else ""


def bootstrap_session(client, base_url: str) -> bool:
    """
    Initialise DVWA DB (if not already done), log in as admin/password, and
    set security level to 'low'. Mutates the client's session cookies.
    Returns True on success.

    Uses the client's own requests.Session throughout so cookie state is shared.
    """
    # Step 1: DB setup — fetch setup.php, grab CSRF token, POST create_db.
    # We use client.session directly (not client.get) to avoid CAPTCHA detection
    # on the setup page triggering adaptive backoff before we've even logged in.
    try:
        resp = client.session.get(f"{base_url}/setup.php", timeout=10)
    except Exception as exc:
        log.warning(f"DVWA setup.php request failed: {exc}")
        return False

    if resp is None or resp.status_code != 200:
        log.warning("DVWA setup.php unreachable")
        return False

    setup_token = _get_token(resp.text)
    try:
        client.session.post(
            f"{base_url}/setup.php",
            data={"create_db": "Create / Reset Database", "user_token": setup_token},
            timeout=10,
        )
    except Exception as exc:
        log.warning(f"DVWA DB setup POST failed: {exc}")
        return False

    log.info("DVWA DB setup step completed")
    time.sleep(1)  # Give MySQL a moment to finish

    # Step 2: Login — fetch login page and grab a fresh CSRF token.
    try:
        resp = client.session.get(f"{base_url}/login.php", timeout=10)
    except Exception as exc:
        log.warning(f"DVWA login page request failed: {exc}")
        return False

    if resp is None or resp.status_code != 200:
        log.warning("DVWA login page unreachable")
        return False

    login_token = _get_token(resp.text)

    # Step 3: POST login credentials.
    try:
        resp = client.session.post(
            f"{base_url}/login.php",
            data={
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": login_token,
            },
            timeout=10,
            allow_redirects=True,
        )
    except Exception as exc:
        log.warning(f"DVWA login POST failed: {exc}")
        return False

    if resp is None:
        log.warning("DVWA login POST returned no response")
        return False

    # Login success: DVWA redirects to index.php (not setup.php or login.php)
    if "login.php" in resp.url or "Login failed" in resp.text:
        log.warning(f"DVWA login failed — redirected to {resp.url}")
        return False

    # Step 4: Ensure security=low cookie is set.
    client.session.cookies.set("security", "low", domain="127.0.0.1")
    log.info("DVWA session bootstrapped (security=low)")
    return True
