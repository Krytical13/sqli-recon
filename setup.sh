#!/usr/bin/env bash
set -euo pipefail

# sqli_recon installer
# Usage: ./setup.sh [--with-headless]

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

# 1. Python check
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        version=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null)
        major=$("$cmd" -c "import sys; print(sys.version_info.major)" 2>/dev/null)
        minor=$("$cmd" -c "import sys; print(sys.version_info.minor)" 2>/dev/null)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 8 ]; then
            PYTHON="$cmd"
            echo "[+] Python $version found ($cmd)"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    echo "[-] Python 3.8+ is required but not found."
    echo "    Install it with your package manager:"
    echo "      Debian/Ubuntu: sudo apt install python3 python3-venv python3-pip"
    echo "      Fedora:        sudo dnf install python3"
    echo "      Arch:          sudo pacman -S python"
    exit 1
fi

# 2. venv check
if ! "$PYTHON" -c "import venv" &>/dev/null; then
    echo "[-] python3-venv is required."
    echo "    Install it with: sudo apt install python3-venv"
    exit 1
fi

# 3. Create virtual environment
if [ ! -d "$VENV_DIR" ]; then
    echo "[+] Creating virtual environment..."
    "$PYTHON" -m venv "$VENV_DIR"
else
    echo "[+] Virtual environment exists"
fi

# 4. Activate and install
source "$VENV_DIR/bin/activate"

echo "[+] Installing sqli_recon and dependencies..."
pip install --upgrade pip -q 2>/dev/null
pip install -e "$SCRIPT_DIR" -q 2>&1 | tail -1

# 5. Optional: Playwright for headless SPA crawling
if [ "$WITH_HEADLESS" = true ]; then
    echo "[+] Installing Playwright..."
    pip install playwright -q 2>&1 | tail -1
    echo "[+] Installing Chromium browser (this may take a minute)..."
    playwright install chromium 2>&1 | tail -2
    echo "[+] Headless SPA crawling enabled"
else
    echo "[*] Headless mode skipped (run with --with-headless to enable)"
fi

# 6. Verify installation
echo ""
echo "[+] Verifying installation..."
ERRORS=0

"$VENV_DIR/bin/python" -c "from sqli_recon.cli import main" 2>/dev/null || { echo "[-] Import check failed"; ERRORS=1; }
"$VENV_DIR/bin/python" -c "import requests, bs4, lxml" 2>/dev/null || { echo "[-] Dependency check failed"; ERRORS=1; }

if [ "$WITH_HEADLESS" = true ]; then
    "$VENV_DIR/bin/python" -c "from playwright.sync_api import sync_playwright" 2>/dev/null || { echo "[-] Playwright check failed"; ERRORS=1; }
fi

if [ "$ERRORS" -eq 0 ]; then
    echo "[+] All checks passed"
fi

# 7. Create wrapper script
WRAPPER="$SCRIPT_DIR/scan"
cat > "$WRAPPER" << 'WRAPPER_EOF'
#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/.venv/bin/activate"
exec python -m sqli_recon "$@"
WRAPPER_EOF
chmod +x "$WRAPPER"

echo ""
echo "=== Setup complete ==="
echo ""
echo "Usage:"
echo "  ./scan -u https://target.com                  # Standard scan"
echo "  ./scan -u https://target.com --tor             # Scan via Tor"
echo "  ./scan -u https://target.com --quick           # Fast recon only"
echo "  ./scan -u https://target.com -o ./results      # Custom output dir"
echo ""
echo "Run ./scan --help for all options."
