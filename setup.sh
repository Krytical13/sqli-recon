#!/usr/bin/env bash
set -euo pipefail

# sqli_recon installer
# Detects OS, installs system prerequisites, creates venv, installs everything.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
WITH_HEADLESS=false

for arg in "$@"; do
    case "$arg" in
        --with-headless) WITH_HEADLESS=true ;;
        --help|-h)
            echo "Usage: ./setup.sh [--with-headless]"
            echo ""
            echo "  --with-headless   Also install Playwright + Chromium for SPA crawling"
            echo "                    (adds ~200MB disk, not needed for most sites)"
            exit 0
            ;;
        *) echo "Unknown option: $arg"; exit 1 ;;
    esac
done

echo "=== sqli_recon setup ==="
echo ""

# ---- Detect package manager ----

PKG_MGR=""
INSTALL_CMD=""
SUDO=""

if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
fi

detect_pkg_manager() {
    if command -v apt-get &>/dev/null; then
        PKG_MGR="apt"
        INSTALL_CMD="$SUDO apt-get install -y"
    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
        INSTALL_CMD="$SUDO dnf install -y"
    elif command -v yum &>/dev/null; then
        PKG_MGR="yum"
        INSTALL_CMD="$SUDO yum install -y"
    elif command -v pacman &>/dev/null; then
        PKG_MGR="pacman"
        INSTALL_CMD="$SUDO pacman -S --noconfirm"
    elif command -v zypper &>/dev/null; then
        PKG_MGR="zypper"
        INSTALL_CMD="$SUDO zypper install -y"
    elif command -v apk &>/dev/null; then
        PKG_MGR="apk"
        INSTALL_CMD="$SUDO apk add"
    elif command -v brew &>/dev/null; then
        PKG_MGR="brew"
        INSTALL_CMD="brew install"
    fi
}

detect_pkg_manager

# Map package names per distro
pkg_python() {
    case "$PKG_MGR" in
        apt)    echo "python3 python3-venv python3-pip python3-dev" ;;
        dnf|yum) echo "python3 python3-pip python3-devel" ;;
        pacman) echo "python python-pip" ;;
        zypper) echo "python3 python3-pip python3-devel" ;;
        apk)    echo "python3 py3-pip python3-dev" ;;
        brew)   echo "python3" ;;
        *)      echo "" ;;
    esac
}

pkg_build_deps() {
    # lxml needs C compiler + libxml2/libxslt headers
    case "$PKG_MGR" in
        apt)    echo "build-essential libxml2-dev libxslt1-dev" ;;
        dnf|yum) echo "gcc libxml2-devel libxslt-devel" ;;
        pacman) echo "base-devel libxml2 libxslt" ;;
        zypper) echo "gcc libxml2-devel libxslt-devel" ;;
        apk)    echo "gcc musl-dev libxml2-dev libxslt-dev" ;;
        brew)   echo "libxml2 libxslt" ;;
        *)      echo "" ;;
    esac
}

# ---- Install system prerequisites ----

install_if_missing() {
    local description="$1"
    local check_cmd="$2"
    local packages="$3"

    if eval "$check_cmd" &>/dev/null; then
        echo "[+] $description: already installed"
        return 0
    fi

    if [ -z "$PKG_MGR" ]; then
        echo "[-] $description: missing, and no supported package manager found."
        echo "    Please install manually: $packages"
        return 1
    fi

    echo "[*] Installing $description..."
    if [ "$PKG_MGR" = "apt" ]; then
        $SUDO apt-get update -qq 2>/dev/null
    fi
    $INSTALL_CMD $packages 2>&1 | tail -3
    echo "[+] $description: installed"
}

# Python 3.8+
install_if_missing \
    "Python 3" \
    "python3 --version" \
    "$(pkg_python)"

# After installing, find the right python binary
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        major=$("$cmd" -c "import sys; print(sys.version_info.major)" 2>/dev/null || echo 0)
        minor=$("$cmd" -c "import sys; print(sys.version_info.minor)" 2>/dev/null || echo 0)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 8 ]; then
            PYTHON="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    echo "[-] Python 3.8+ is required but could not be found after install attempt."
    exit 1
fi

version=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "[+] Using Python $version ($PYTHON)"

# python3-venv + ensurepip — on Debian/Ubuntu these come from python3.X-venv
# "import venv" can succeed even when ensurepip is missing, so we test by
# actually creating a throwaway venv.
PY_VER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
VENV_TEST_DIR=$(mktemp -d)
if "$PYTHON" -m venv "$VENV_TEST_DIR/test" &>/dev/null; then
    echo "[+] python3-venv: already installed"
else
    echo "[*] Installing python${PY_VER}-venv..."
    if [ "$PKG_MGR" = "apt" ]; then
        $SUDO apt-get update -qq 2>/dev/null
        $INSTALL_CMD "python${PY_VER}-venv" 2>/dev/null \
            || $INSTALL_CMD python3-venv 2>/dev/null \
            || { echo "[-] Failed. Try: sudo apt install python${PY_VER}-venv"; exit 1; }
    elif [ -n "$INSTALL_CMD" ]; then
        $INSTALL_CMD $(pkg_python) 2>/dev/null
    fi
    # Verify it actually works now
    if ! "$PYTHON" -m venv "$VENV_TEST_DIR/test2" &>/dev/null; then
        echo "[-] python3-venv still broken after install."
        echo "    Try manually: sudo apt install python${PY_VER}-venv"
        exit 1
    fi
    echo "[+] python${PY_VER}-venv: installed"
fi
rm -rf "$VENV_TEST_DIR"

# pip (sometimes missing on minimal installs)
if ! "$PYTHON" -m pip --version &>/dev/null; then
    echo "[*] Installing pip..."
    if [ "$PKG_MGR" = "apt" ]; then
        $SUDO apt-get update -qq 2>/dev/null
        $INSTALL_CMD python3-pip 2>/dev/null || true
    elif [ -n "$INSTALL_CMD" ]; then
        $INSTALL_CMD $(pkg_python) 2>/dev/null || true
    fi
    # Fallback: ensurepip
    if ! "$PYTHON" -m pip --version &>/dev/null; then
        "$PYTHON" -m ensurepip --upgrade 2>/dev/null || true
    fi
    echo "[+] pip: installed"
else
    echo "[+] pip: already installed"
fi

# Build dependencies for lxml (C extension)
install_if_missing \
    "Build tools (for lxml)" \
    "xml2-config --version" \
    "$(pkg_build_deps)"

# ---- Create virtual environment ----

echo ""
if [ -d "$VENV_DIR" ]; then
    # Verify existing venv is usable (activate script exists and python works)
    if [ ! -f "$VENV_DIR/bin/activate" ] || ! "$VENV_DIR/bin/python" --version &>/dev/null; then
        echo "[*] Existing virtual environment is broken, recreating..."
        rm -rf "$VENV_DIR"
    fi
fi

if [ ! -d "$VENV_DIR" ]; then
    echo "[+] Creating virtual environment..."
    "$PYTHON" -m venv "$VENV_DIR"
else
    echo "[+] Virtual environment exists"
fi

source "$VENV_DIR/bin/activate"

# ---- Install Python packages ----

echo "[+] Installing sqli_recon and dependencies..."
pip install --upgrade pip -q 2>/dev/null
pip install -e "$SCRIPT_DIR" -q 2>&1 | tail -1

# ---- Exploitation tools (sqlmap, commix, tplmap) ----

echo "[+] Installing sqlmap..."
pip install sqlmap -q 2>&1 | tail -1

echo "[+] Installing commix..."
pip install git+https://github.com/commixproject/commix.git -q 2>&1 | tail -1 \
    || echo "[*] commix install failed — command injection testing will be skipped"

echo "[+] Installing tplmap..."
TPLMAP_DIR="$SCRIPT_DIR/tools/tplmap"
if [ ! -d "$TPLMAP_DIR" ]; then
    git clone --depth 1 https://github.com/epinna/tplmap.git "$TPLMAP_DIR" 2>&1 | tail -1 \
        || echo "[*] tplmap clone failed — SSTI testing will be skipped"
fi
# Install tplmap deps (ignore wsgiref build error — Python 2 leftover)
pip install pyyaml -q 2>/dev/null

# ---- Optional: Playwright ----

if [ "$WITH_HEADLESS" = true ]; then
    echo "[+] Installing Playwright..."
    pip install playwright -q 2>&1 | tail -1

    # Playwright needs browser binaries + system deps
    echo "[+] Installing Playwright system dependencies..."
    if [ "$PKG_MGR" = "apt" ]; then
        # playwright install-deps installs the right libs for the OS
        $SUDO "$VENV_DIR/bin/playwright" install-deps chromium 2>&1 | tail -3
    fi

    echo "[+] Installing Chromium browser (this may take a minute)..."
    "$VENV_DIR/bin/playwright" install chromium 2>&1 | tail -2
    echo "[+] Headless SPA crawling enabled"
else
    echo "[*] Headless mode skipped (run with --with-headless to enable)"
fi

# ---- Verify ----

echo ""
echo "[+] Verifying installation..."
ERRORS=0

"$VENV_DIR/bin/python" -c "from sqli_recon.cli import main" 2>/dev/null \
    && echo "    sqli_recon .... ok" \
    || { echo "    sqli_recon .... FAILED"; ERRORS=1; }

"$VENV_DIR/bin/python" -c "import requests, bs4, lxml" 2>/dev/null \
    && echo "    dependencies .. ok" \
    || { echo "    dependencies .. FAILED"; ERRORS=1; }

if [ "$WITH_HEADLESS" = true ]; then
    "$VENV_DIR/bin/python" -c "from playwright.sync_api import sync_playwright" 2>/dev/null \
        && echo "    playwright .... ok" \
        || { echo "    playwright .... FAILED"; ERRORS=1; }
fi

if [ "$ERRORS" -ne 0 ]; then
    echo ""
    echo "[-] Some checks failed. Review the output above."
    exit 1
fi

# ---- Create wrapper scripts ----

for tool in scan:sqli_recon map:infra_map; do
    TOOL_NAME="${tool%%:*}"
    TOOL_MODULE="${tool##*:}"
    WRAPPER="$SCRIPT_DIR/$TOOL_NAME"
    cat > "$WRAPPER" << WRAPPER_EOF
#!/usr/bin/env bash
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
source "\$SCRIPT_DIR/.venv/bin/activate"
exec python -m $TOOL_MODULE "\$@"
WRAPPER_EOF
    chmod +x "$WRAPPER"
done

echo ""
echo "=== Setup complete ==="
echo ""
echo "Tools:"
echo "  ./scan -u https://target.com              # SQLi surface discovery"
echo "  ./map example.com                          # Infrastructure mapping"
echo ""
echo "Examples:"
echo "  ./scan -u https://target.com --tor         # Scan via Tor"
echo "  ./map example.com --depth 3 -o ./results   # Deep mapping with output"
echo "  ./map 93.184.216.34 --tor                  # Map from an IP via Tor"
echo ""
echo "Run ./scan --help or ./map --help for all options."
