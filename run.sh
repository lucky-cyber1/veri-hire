#!/usr/bin/env bash
set -e

echo "=================================================="
echo "  Starting VeriHire AI Defense Server"
echo "=================================================="

if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required. Please install Python 3.10+."
    exit 1
fi

if [ ! -d "venv" ]; then
    echo "Initializing virtual environment..."
    python3 -m venv venv
    ./venv/bin/pip install --upgrade pip
    ./venv/bin/pip install -r requirements.txt
fi

echo "VeriHire running at: http://127.0.0.1:8000"
echo "Pro Tier Link:       http://127.0.0.1:8000/?tier=pro"
echo "Free Tier Link:      http://127.0.0.1:8000/?tier=free"
PYTHONPATH=. ./venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
