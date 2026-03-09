#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  Proxmark3 NiceGUI – setup & run
#  Creates / reuses a virtual-environment named .pm3
# ─────────────────────────────────────────────────────────────
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.pm3"
PYTHON="python3"

# ── 1. Create venv if it doesn't exist ───────────────────────
if [ ! -d "$VENV_DIR" ]; then
    echo "[setup] Creating virtual environment at $VENV_DIR …"
    $PYTHON -m venv "$VENV_DIR"
fi

# ── 2. Activate ──────────────────────────────────────────────
source "$VENV_DIR/bin/activate"

# ── 3. Install / upgrade dependencies ────────────────────────
echo "[setup] Installing dependencies …"
pip install --quiet --upgrade pip
pip install --quiet nicegui pyserial

# ── 4. Launch ────────────────────────────────────────────────
echo "[setup] Starting Proxmark3 GUI on http://0.0.0.0:8080 …"
exec python "$SCRIPT_DIR/proxmark3_gui.py"
