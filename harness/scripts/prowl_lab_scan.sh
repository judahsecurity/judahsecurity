#!/usr/bin/env bash
# Run one Prowl assessment from a bare checkout, with no Docker and no platform.
#
# Starts a throwaway Postgres, creates the schema and one lab org/user, builds a
# Python 3.12 venv with the assessment requirements, then runs the in-product
# agent through local_harness.product_agent with the normal publication gates.
#
#   ANTHROPIC_API_KEY=... harness/scripts/prowl_lab_scan.sh https://ginandjuice.shop
#
# Only scan targets you are authorized to test. ginandjuice.shop is PortSwigger's
# public, intentionally vulnerable demo app.
#
# Environment knobs (defaults in brackets):
#   PROWL_LAB_DIR [./runs/prowl_lab]   work dir: venv, database, results
#   MAX_ITERATIONS [30]  MAX_TURNS [4]  PRICE_LIMIT_USD [5]
#   ASSESSMENT_MODE [standard|deep]
#   AGENT_SETTLEMENT_BACKFILL [true]   save unsubmitted leads at budget end
set -euo pipefail

TARGET="${1:?usage: $0 <target-url> [scope]}"
SCOPE="${2:-$TARGET}"
: "${ANTHROPIC_API_KEY:?set ANTHROPIC_API_KEY (Prowl calls the Anthropic API directly)}"

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
LAB="$(mkdir -p "${PROWL_LAB_DIR:-$REPO/runs/prowl_lab}" && cd "${PROWL_LAB_DIR:-$REPO/runs/prowl_lab}" && pwd)"
PG_BIN="${PG_BIN:-$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)}"
PG_PORT="${PG_PORT:-5433}"
PY="$LAB/venv/bin/python"

# 1. Python 3.12 venv (pinned SQLAlchemy does not run on 3.13).
if [ ! -x "$PY" ]; then
  if command -v uv >/dev/null; then
    uv venv -q -p python3.12 "$LAB/venv"
    uv pip install -q -p "$PY" -r "$REPO/backend/requirements-assessment-tests.txt"
  else
    python3.12 -m venv "$LAB/venv"
    "$PY" -m pip install -q -r "$REPO/backend/requirements-assessment-tests.txt"
  fi
fi

# 2. Throwaway Postgres (runs as the postgres user when invoked as root).
if [ -z "$PG_BIN" ]; then echo "Postgres binaries not found; set PG_BIN" >&2; exit 1; fi
run_pg() { if [ "$(id -u)" = 0 ]; then su postgres -s /bin/bash -c "$*"; else bash -c "$*"; fi; }
mkdir -p "$LAB/pg"
if [ "$(id -u)" = 0 ]; then
  id postgres >/dev/null 2>&1 || useradd -r postgres
  chown postgres "$LAB/pg"
  # postgres must be able to traverse to the data dir.
  d="$LAB"; while [ "$d" != / ]; do chmod o+x "$d" 2>/dev/null || true; d="$(dirname "$d")"; done
fi
[ -d "$LAB/pg/data" ] || run_pg "$PG_BIN/initdb -D '$LAB/pg/data' -A trust -U postgres >/dev/null"
if ! "$PG_BIN/pg_isready" -q -h 127.0.0.1 -p "$PG_PORT"; then
  run_pg "$PG_BIN/pg_ctl -D '$LAB/pg/data' -l '$LAB/pg/log' -o '-p $PG_PORT -k $LAB/pg' -w start >/dev/null"
fi
psql -h 127.0.0.1 -p "$PG_PORT" -U postgres -tc "select 1 from pg_database where datname='prowl_lab'" \
  | grep -q 1 || psql -q -h 127.0.0.1 -p "$PG_PORT" -U postgres -c "create database prowl_lab"

export DATABASE_URL="postgresql://postgres@127.0.0.1:$PG_PORT/prowl_lab"
export AEGIS_ASSESSMENT_DATABASE_URL="$DATABASE_URL"
export SECRET_KEY="${SECRET_KEY:-prowl-lab-only-secret-with-at-least-32-characters}"
export PYTHONPATH="$REPO/backend:$REPO/harness:$REPO/backend/packages/aegis_praetorium:$REPO/backend/packages/asm_scanner_core"
export AEGIS_EVIDENCE_DIR="$LAB/evidence"
export AGENT_SETTLEMENT_BACKFILL="${AGENT_SETTLEMENT_BACKFILL:-true}"
# A sandbox's ANTHROPIC_BASE_URL may point at its own proxy; Prowl needs the real API.
unset ANTHROPIC_BASE_URL

# 3. Schema plus one lab org/user.
read -r ORG_ID USER_ID < <("$PY" - <<'EOF'
import importlib, pkgutil
import app.models as models
from app.db.database import Base, engine, SessionLocal
for m in pkgutil.iter_modules(models.__path__):
    importlib.import_module(f"app.models.{m.name}")
Base.metadata.create_all(bind=engine)
from app.models.organization import Organization
from app.models.user import User
def pick(model, values):
    cols = {c.name for c in model.__table__.columns}
    return model(**{k: v for k, v in values.items() if k in cols})
with SessionLocal() as db:
    org = db.query(Organization).first()
    if not org:
        org = pick(Organization, {"name": "Prowl Lab", "slug": "prowl-lab"})
        db.add(org); db.flush()
    user = db.query(User).first()
    if not user:
        user = pick(User, {"email": "lab@prowl.local", "username": "prowl-lab",
                           "hashed_password": "!", "organization_id": org.id, "is_active": True})
        db.add(user)
    db.commit()
    print(org.id, user.id)
EOF
)

# 4. Run the assessment. Each run gets its own results directory.
OUT="$LAB/results/$(echo "$TARGET" | sed -E 's#^https?://##; s#[^A-Za-z0-9.]+#_#g')/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"
export AEGIS_FINDINGS_SINK="$OUT/findings.jsonl"
echo "Prowl -> $TARGET (scope $SCOPE), org $ORG_ID user $USER_ID, results in $OUT"
set +e
"$PY" -m local_harness.product_agent --target "$TARGET" --scope "$SCOPE" \
  --organization-id "$ORG_ID" --user-id "$USER_ID" \
  --max-turns "${MAX_TURNS:-4}" --max-iterations "${MAX_ITERATIONS:-30}" \
  --price-limit-usd "${PRICE_LIMIT_USD:-5}" --assessment-mode "${ASSESSMENT_MODE:-standard}" \
  2>&1 | tee "$OUT/run.log"
status=${PIPESTATUS[0]}
set -e
echo "exit $status; findings: $(wc -l < "$AEGIS_FINDINGS_SINK") in $AEGIS_FINDINGS_SINK"
echo "summary: $OUT/product_assessment.json"
exit "$status"
