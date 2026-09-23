#!/bin/bash
# Deploy one tested branch to the standalone production host.
set -euo pipefail

EC2_IP="${1:-}"
KEY_FILE="${2:-${HOME}/.ssh/id_rsa}"
APP_DIR="${APP_DIR:-/opt/asm}"
SSH_USER="${SSH_USER:-ubuntu}"
DEPLOY_REF="${DEPLOY_REF:-main}"
DEPLOY_EXPECTED_SHA="${DEPLOY_EXPECTED_SHA:-}"

if [ -z "$EC2_IP" ]; then
  echo "Usage: $0 <EC2_IP> [path/to/key.pem]"
  exit 1
fi
if [[ ! "$DEPLOY_REF" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]]; then
  echo "DEPLOY_REF must be a branch name without shell metacharacters." >&2
  exit 1
fi
if [ -n "$DEPLOY_EXPECTED_SHA" ] && [[ ! "$DEPLOY_EXPECTED_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "DEPLOY_EXPECTED_SHA must be a full lowercase commit SHA." >&2
  exit 1
fi

SSH_OPTS=(-o StrictHostKeyChecking=no -o ConnectTimeout=10)
[ -f "$KEY_FILE" ] && SSH_OPTS+=(-i "$KEY_FILE")

echo "Deploying $DEPLOY_REF to $SSH_USER@$EC2_IP:$APP_DIR"

ssh "${SSH_OPTS[@]}" "$SSH_USER@$EC2_IP" bash -s -- "$APP_DIR" "$DEPLOY_REF" "$DEPLOY_EXPECTED_SHA" <<'REMOTE'
set -euo pipefail
app_dir="$1"
deploy_ref="$2"
expected_sha="$3"
cd "$app_dir"

if [ -n "$(git status --porcelain)" ]; then
  echo "Production checkout has uncommitted changes; refusing deployment." >&2
  exit 1
fi

previous_ref="$(git rev-parse HEAD)"
previous_branch="$(git branch --show-current)"
deployment_started=0

rollback() {
  status=$?
  if [ "$status" -eq 0 ] || [ "$deployment_started" -eq 0 ]; then
    return
  fi
  trap - EXIT
  echo "Deployment failed; restoring $previous_ref" >&2
  git switch "$previous_branch"
  git reset --hard "$previous_ref"
  mapfile -t available < <(sudo docker compose config --services)
  build_services=()
  run_services=()
  for service in backend scanner intel-refresher severity-worker frontend aegis-oracle; do
    if printf '%s\n' "${available[@]}" | grep -qx "$service"; then
      build_services+=("$service")
    fi
  done
  for service in oast-worker backend scanner scheduler intel-refresher severity-worker frontend aegis-oracle neo4j nginx; do
    if printf '%s\n' "${available[@]}" | grep -qx "$service"; then
      run_services+=("$service")
    fi
  done
  if ! printf '%s\n' "${available[@]}" | grep -qx severity-worker; then
    sudo docker rm -f asm_severity_worker 2>/dev/null || true
  fi
  sudo docker compose build "${build_services[@]}"
  sudo docker compose up -d "${run_services[@]}"
  # Nginx resolves Compose service names when its configuration is loaded.
  # Reload it after upstream containers are replaced so it does not retain a
  # stale backend/frontend address during rollback.
  if printf '%s\n' "${available[@]}" | grep -qx nginx; then
    sudo docker compose restart nginx
  fi
  if sudo systemctl list-unit-files asm-interceptor-worker.service --no-legend 2>/dev/null | grep -q asm-interceptor-worker; then
    sudo systemctl restart asm-interceptor-browser.service asm-interceptor-worker.service
  fi
  exit "$status"
}
trap rollback EXIT

echo "[1/7] Fetching and selecting the deployment revision"
git fetch origin "$deploy_ref"
fetched_ref="$(git rev-parse FETCH_HEAD)"
if [ -n "$expected_sha" ] && [ "$fetched_ref" != "$expected_sha" ]; then
  echo "The requested branch moved after validation; refusing unvalidated revision $fetched_ref." >&2
  exit 1
fi
git switch "$deploy_ref"
git merge --ff-only "origin/$deploy_ref"
deployed_ref="$(git rev-parse HEAD)"
deployment_started=1

echo "[2/7] Validating Compose"
sudo docker compose config --quiet

echo "[3/7] Backing up Postgres"
mkdir -p backups
backup="backups/pre-deploy-$(date -u +%Y%m%dT%H%M%SZ)-${previous_ref:0:12}.sql.gz"
sudo docker exec asm_database sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' | gzip > "$backup"
find backups -type f -name 'pre-deploy-*.sql.gz' -mtime +14 -delete

echo "[4/7] Building images"
# scanner and scheduler intentionally share SCANNER_IMAGE; build it once.
sudo docker compose build backend scanner intel-refresher severity-worker frontend aegis-oracle

echo "[5/7] Starting services"
sudo docker compose up -d oast-worker backend scanner scheduler intel-refresher severity-worker frontend aegis-oracle neo4j nginx
# Re-resolve backend and frontend service names after Compose recreates them.
sudo docker compose restart nginx

echo "[6/7] Running additive migrations"
sudo docker exec asm_backend python scripts/migrate_add_oracle_columns.py --backfill 2>/dev/null || true
sudo docker exec asm_backend python scripts/migrate_agent_knowledge_embeddings.py
sudo docker exec asm_backend python scripts/migrate_commoncrawl_enum.py

# A host Interceptor worker imports the checked-out backend package. Restart it
# after the checkout changes so its runtime contract matches the API revision.
if sudo systemctl list-unit-files asm-interceptor-worker.service --no-legend 2>/dev/null | grep -q asm-interceptor-worker; then
  sudo systemctl restart asm-interceptor-browser.service asm-interceptor-worker.service
fi

echo "[7/7] Running production gates"
for attempt in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:8000/health >/dev/null; then
    break
  fi
  if [ "$attempt" -eq 30 ]; then
    echo "Backend health check failed" >&2
    exit 1
  fi
  sleep 2
done
sudo docker exec asm_backend python /app/scripts/check_interactsh.py --live --timeout 30
if sudo systemctl list-unit-files asm-interceptor-worker.service --no-legend 2>/dev/null | grep -q asm-interceptor-worker; then
  for attempt in $(seq 1 30); do
    if sudo docker exec asm_backend python -c \
      'from app.services.recon_jobs_service import online_kinds; raise SystemExit(0 if "ubuntu" in online_kinds() else 1)'; then
      break
    fi
    if [ "$attempt" -eq 30 ]; then
      sudo journalctl -u asm-interceptor-browser.service -u asm-interceptor-worker.service -n 100 --no-pager >&2
      echo "Interceptor worker failed its deployment readiness gate" >&2
      exit 1
    fi
    sleep 2
  done
fi
unhealthy="$(sudo docker compose ps --format json | python3 -c '
import json, sys
bad=[]
for line in sys.stdin:
    row=json.loads(line)
    if row.get("State") != "running" or row.get("Health") == "unhealthy":
        bad.append(row.get("Service"))
print(",".join(filter(None, bad)))
')"
if [ -n "$unhealthy" ]; then
  echo "Unhealthy services: $unhealthy" >&2
  exit 1
fi

trap - EXIT
echo "Deployment complete: $deployed_ref"
REMOTE
