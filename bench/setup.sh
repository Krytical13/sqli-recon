#!/usr/bin/env bash
set -euo pipefail

# bench/ — detector accuracy harness installer (DEV-ONLY, not end users)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== bench setup ==="

# Verify we're in a sqli-recon checkout
if [ ! -f "$REPO_ROOT/pyproject.toml" ]; then
    echo "[-] Run this from inside a sqli-recon checkout."
    exit 1
fi

# Re-use the project venv if it exists (created by top-level setup.sh)
if [ -d "$REPO_ROOT/.venv" ]; then
    echo "[+] Reusing existing venv at $REPO_ROOT/.venv"
    source "$REPO_ROOT/.venv/bin/activate"
else
    echo "[-] No .venv found. Run ./setup.sh in the repo root first."
    exit 1
fi

# Install bench extras (currently just PyYAML)
echo "[+] Installing bench extras..."
pip install -e "$REPO_ROOT[bench]" -q 2>&1 | tail -1

# Verify docker (required for DVWA)
if command -v docker &>/dev/null; then
    echo "[+] Docker found: $(docker --version)"
    echo "[*] Pulling DVWA image (this may take a minute)..."
    docker pull vulnerables/web-dvwa:latest 2>&1 | tail -2
else
    echo "[!] Docker not found — DVWA corpus will be skipped."
    echo "    Install docker to enable: https://docs.docker.com/engine/install/"
fi

echo ""
echo "=== bench setup complete ==="
echo ""
echo "Run: python -m bench"
