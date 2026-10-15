#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
fi
if ! .venv/bin/python -c "import fastapi, uvicorn, httpx" 2>/dev/null; then
  .venv/bin/pip install -r requirements.txt
fi
exec .venv/bin/python -m uvicorn aegis.app:app --host 127.0.0.1 --port "${PORT:-8090}"
