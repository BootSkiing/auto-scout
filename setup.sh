#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Auto-Scout - Setup ==="
echo ""

# Python dependencies
echo "[1/5] Installing Python dependencies..."
pip3 install -r requirements.txt
echo "  Done."

# bbot (installed in isolation -- it is used as a CLI, not imported)
echo "[*] Checking bbot..."
if command -v bbot &>/dev/null; then
    echo "  bbot already installed: $(bbot --version 2>&1 | head -1)"
elif command -v pipx &>/dev/null; then
    echo "  Installing bbot with pipx (isolated environment)..."
    if pipx install bbot; then
        echo "  Installed bbot. Ensure pipx's bin dir is on your PATH (run: pipx ensurepath)."
    else
        echo "  pipx install failed. Install manually: pipx install bbot"
    fi
else
    echo "  pipx not found -- recommended for installing bbot (a CLI tool)."
    echo "  Install pipx, then bbot:"
    echo "    python3 -m pip install --user pipx && python3 -m pipx ensurepath"
    echo "    pipx install bbot"
    echo "  (Or, if you prefer: python3 -m pip install --user bbot -- may conflict"
    echo "   with this project's pinned dependencies.)"
fi

# masscan
echo "[2/5] Checking masscan..."
if command -v masscan &>/dev/null; then
    echo "  masscan already installed: $(masscan --version 2>&1 | head -1)"
else
    echo "  masscan not found. Install with:"
    echo "    sudo apt install masscan"
    echo "  Or build from source:"
    echo "    git clone https://github.com/robertdavidgraham/masscan && cd masscan && make && sudo make install"
    echo "  (Skipping for now -- stage 7 will fall back to nmap-only if masscan is missing)"
fi

# gowitness
echo "[3/5] Checking gowitness..."
if command -v gowitness &>/dev/null; then
    echo "  gowitness already installed: $(gowitness version 2>&1 | head -1)"
else
    echo "  gowitness not found. Attempting to download..."
    GOWITNESS_VERSION="3.0.5"
    GOWITNESS_URL="https://github.com/sensepost/gowitness/releases/download/${GOWITNESS_VERSION}/gowitness-${GOWITNESS_VERSION}-linux-amd64"
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
    if curl -fSL -o "${INSTALL_DIR}/gowitness" "$GOWITNESS_URL"; then
        chmod +x "${INSTALL_DIR}/gowitness"
        echo "  Installed gowitness ${GOWITNESS_VERSION} to ${INSTALL_DIR}/gowitness"
        echo "  Make sure ${INSTALL_DIR} is in your PATH"
    else
        echo "  Download failed. Install gowitness manually from:"
        echo "    https://github.com/sensepost/gowitness/releases"
    fi
fi

# Chrome/Chromium (required by gowitness)
echo "[4/6] Checking Chrome/Chromium..."
CHROME_BIN=""
for bin in google-chrome chromium-browser chromium chrome; do
    if command -v "$bin" &>/dev/null; then
        CHROME_BIN="$bin"
        break
    fi
done
if [ -n "$CHROME_BIN" ]; then
    echo "  Found: $CHROME_BIN"
else
    echo "  ✗ No Chrome or Chromium browser found."
    echo "    gowitness (stage 8) requires a Chrome/Chromium binary to take screenshots."
    echo "    Install one of:"
    echo "      sudo apt install chromium-browser"
    echo "      sudo apt install google-chrome-stable"
    echo "    Or use --chrome-path with gowitness to point to a custom binary."
fi

# Config bootstrap
echo "[*] Checking config.yaml..."
if [ -f "config.yaml" ]; then
    echo "  config.yaml already exists"
else
    cp config.example.yaml config.yaml
    echo "  Created config.yaml from config.example.yaml -- add your API keys."
fi

# Seed files
echo "[5/6] Checking seed files..."
if [ -f "seeds/corporations.txt" ] && [ -f "seeds/domains.txt" ]; then
    echo "  Seed files present in seeds/ (shipped with example data)."
    echo "  Edit them with your authorized target scope before running."
else
    echo "  WARNING: expected seed files are missing from seeds/."
    echo "  Restore them from the repo or see the README 'Seed Files' section."
fi

# Tool validation
echo "[6/6] Validating tools..."
MISSING=0
for tool in python3 nmap bbot dig curl jq; do
    if command -v "$tool" &>/dev/null; then
        echo "  ✓ $tool"
    else
        echo "  ✗ $tool -- NOT FOUND"
        MISSING=$((MISSING + 1))
    fi
done

for tool in masscan gowitness; do
    if command -v "$tool" &>/dev/null; then
        echo "  ✓ $tool"
    else
        echo "  ? $tool -- optional, not found (some stages will have reduced functionality)"
    fi
done

echo ""
if [ "$MISSING" -gt 0 ]; then
    echo "WARNING: $MISSING required tool(s) missing. Install them before running the pipeline."
else
    echo "Setup complete. Next steps:"
    echo "  1. Edit config.yaml with your API keys"
    echo "  2. Populate seed files in seeds/"
    echo "  3. Run: ./run.sh"
fi
