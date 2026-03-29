"""Configuration — loads API keys from config file or environment variables.

Keys are optional. If absent, those sources are skipped silently.
Config file: ~/.config/infra_map/keys.conf
"""

import os
import configparser

CONFIG_DIR = os.path.expanduser("~/.config/infra_map")
CONFIG_FILE = os.path.join(CONFIG_DIR, "keys.conf")

TEMPLATE = """\
# infra_map API keys (all optional — tool works without them)
# These enhance results when present.

[keys]
# Get yours at: https://account.shodan.io
# Free tier: limited queries. $49 one-time membership unlocks API.
shodan =

# Get yours at: https://search.censys.io/account/api
# Free tier: 250 queries/month.
censys_id =
censys_secret =
"""


def load_keys():
    """Load API keys from config file, falling back to environment variables."""
    keys = {
        "shodan": "",
        "censys_id": "",
        "censys_secret": "",
    }

    # Config file
    if os.path.exists(CONFIG_FILE):
        cfg = configparser.ConfigParser()
        cfg.read(CONFIG_FILE)
        if cfg.has_section("keys"):
            for key in keys:
                val = cfg.get("keys", key, fallback="").strip()
                if val:
                    keys[key] = val

    # Environment variables override config file
    env_map = {
        "shodan": "SHODAN_API_KEY",
        "censys_id": "CENSYS_API_ID",
        "censys_secret": "CENSYS_API_SECRET",
    }
    for key, env_var in env_map.items():
        val = os.environ.get(env_var, "").strip()
        if val:
            keys[key] = val

    return keys


def setup_config():
    """Create config file template if it doesn't exist."""
    if os.path.exists(CONFIG_FILE):
        return CONFIG_FILE

    os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        f.write(TEMPLATE)
    os.chmod(CONFIG_FILE, 0o600)
    return CONFIG_FILE


def has_any_keys(keys):
    """Check if any API keys are configured."""
    return any(v for v in keys.values())
