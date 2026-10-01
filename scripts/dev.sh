#!/usr/bin/env bash
# Development helper: backend on :8000 with reload + Vite dev server on :5173 (proxies /api).
set -euo pipefail
cd "$(dirname "$0")/.."
python -m backend.main --reload &
BACK=$!
trap 'kill $BACK 2>/dev/null || true' EXIT
cd frontend
[ -d node_modules ] || npm install
npm run dev
