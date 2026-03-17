#!/usr/bin/env bash
# AegisX Backend — one-command startup
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "──────────────────────────────────────────"
echo "  AegisX Backend Startup"
echo "──────────────────────────────────────────"

# Check Python
if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 not found. Please install Python 3.9+"
  exit 1
fi

# Install dependencies if needed
echo "[1/3] Checking dependencies..."
pip install -q -r requirements.txt

# Check Ollama (optional)
echo "[2/3] Checking Ollama..."
if curl -s http://localhost:11434/api/version &>/dev/null; then
  echo "      Ollama is running ✓"
else
  echo "      Ollama not found — AI will use rule-based fallback (still works!)"
  echo "      To enable AI: https://ollama.com  →  ollama pull llama3"
fi

# Start server
echo "[3/3] Starting AegisX on http://localhost:8000 ..."
echo ""
python3 app.py
