#!/bin/bash
# =============================================================================
# Push latest code and restart services on EC2
# =============================================================================
# Usage: ./scripts/push-to-ec2.sh <EC2_IP> [path/to/key.pem]
#
# Example:
#   ./scripts/push-to-ec2.sh 1.2.3.4 ~/.ssh/mykey.pem
# =============================================================================
set -euo pipefail

EC2_IP="${1:-}"
KEY_FILE="${2:-~/.ssh/id_rsa}"
APP_DIR="${APP_DIR:-/opt/asm}"
SSH_USER="${SSH_USER:-ubuntu}"

if [ -z "$EC2_IP" ]; then
  echo "Usage: $0 <EC2_IP> [path/to/key.pem]"
  exit 1
fi

SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10"
[ -f "$KEY_FILE" ] && SSH_OPTS="$SSH_OPTS -i $KEY_FILE"

echo "→ Deploying to $SSH_USER@$EC2_IP:$APP_DIR"

ssh $SSH_OPTS "$SSH_USER@$EC2_IP" bash <<EOF
  set -e
  cd $APP_DIR

  echo "[1/5] Pulling latest code..."
  git pull

  echo "[2/5] Rebuilding changed images..."
  # backend  — API routes, services, models
  # scanner  — scanner_worker.py (CommonCrawl handler, in_scope guards)
  # scheduler — schedule_worker.py (daily CC refresh)
  # frontend  — settings page UI updates
  docker compose build backend scanner scheduler intel-refresher frontend aegis-oracle

  echo "[3/5] Restarting services..."
  docker compose up -d --no-deps backend scanner scheduler intel-refresher frontend aegis-oracle nginx

  echo "[4/5] Running migrations..."
  # Oracle columns (existing)
  docker exec asm_backend python scripts/migrate_add_oracle_columns.py --backfill 2>/dev/null || true
  # agent_knowledge embedding columns
  docker exec asm_backend python scripts/migrate_agent_knowledge_embeddings.py
  # CommonCrawl: add enum value + create project-settings rows for all orgs
  docker exec asm_backend python scripts/migrate_commoncrawl_enum.py

  echo "[5/5] Health check..."
  sleep 5
  docker compose ps

  echo ""
  echo "✓ Deploy complete."
EOF
