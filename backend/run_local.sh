#!/usr/bin/env bash
# Run the backend directly on the host (macOS/dev), pointed at the dockerized
# Postgres + Redis. Security-tool binaries that aren't installed locally are
# simply skipped by the agent's availability preflight.
#
# Usage:  ./run_local.sh          # start uvicorn on :8000
#         ./run_local.sh init     # (re)create schema + seed default users, then exit
set -euo pipefail

cd "$(dirname "$0")"

PY=.venv311/bin/python

# Editable local packages (packages/aegis_praetorium, packages/asm_scanner_core)
# are installed via .pth files, but site's .pth processing has proven flaky for
# one of them here. Put both source roots on PYTHONPATH so imports are reliable.
export PYTHONPATH="$PWD/packages/aegis_praetorium:$PWD/packages/asm_scanner_core${PYTHONPATH:+:$PYTHONPATH}"

# --- Infra endpoints (dockerized db/redis published on localhost) ------------
export DATABASE_URL="${DATABASE_URL:-postgresql://asm_user:asm_password@localhost:5432/asm_db}"
export REDIS_URL="${REDIS_URL:-redis://localhost:6379/0}"

# EvoGraph cross-session learning "brain" (dockerized Neo4j published on
# localhost). The in-container default hostname is `neo4j`, which the host can't
# resolve — point at localhost so EvoGraph connects instead of silently
# disabling cross-session learning.
export NEO4J_URI="${NEO4J_URI:-bolt://localhost:7687}"
export NEO4J_USER="${NEO4J_USER:-neo4j}"
export NEO4J_PASSWORD="${NEO4J_PASSWORD:-neo4j_password}"

# --- Security-tool binaries on PATH -----------------------------------------
# Homebrew installs (katana, httpx, naabu, ffuf, feroxbuster, gau, dnsx,
# subfinder, nuclei, sqlmap, nikto, dalfox, gitleaks) live in /opt/homebrew/bin;
# Go-installed tools (waybackurls, assetfinder, subfaster) land in $HOME/go/bin.
# wpscan is a Ruby gem installed under a dedicated GEM_HOME with Homebrew's
# modern Ruby (system Ruby 2.6 is too old for it). Python-based CLIs (wafw00f,
# arjun) live in the backend venv's bin. The agent finds tools via shutil.which,
# so every install location must be on PATH.
export GEM_HOME="${GEM_HOME:-$HOME/.gem-wpscan}"
export PATH="/opt/homebrew/bin:/opt/homebrew/opt/ruby/bin:$GEM_HOME/bin:$HOME/go/bin:$PWD/.venv311/bin:$PATH"

# Playwright's managed Chromium (deep_crawl / interceptor). Installed outside
# the iCloud-synced project tree because Playwright's lockfile heartbeat breaks
# on synced filesystems.
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}"

# --- Writable data/output dirs (containers use /app/... which is read-only here)
LOCAL_DATA="$PWD/.local_data"
LOCAL_OUT="$PWD/.local_outputs"
export SCREENSHOTS_DIR="${SCREENSHOTS_DIR:-$LOCAL_DATA/screenshots}"
export PANORAMA_DATA_DIR="${PANORAMA_DATA_DIR:-$LOCAL_DATA/panorama}"
export SNI_DATA_DIR="${SNI_DATA_DIR:-$LOCAL_DATA/sni-ip-ranges}"
export WORKFLOW_OUTPUT_DIR="${WORKFLOW_OUTPUT_DIR:-$LOCAL_OUT/workflows}"
mkdir -p "$SCREENSHOTS_DIR" "$PANORAMA_DATA_DIR" "$SNI_DATA_DIR" "$WORKFLOW_OUTPUT_DIR"

export DEBUG="${DEBUG:-true}"

if [ "${1:-}" = "init" ]; then
  exec "$PY" -m app.scripts.init_db
fi

exec "$PY" -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --timeout-keep-alive 300
