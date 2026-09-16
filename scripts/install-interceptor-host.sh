#!/bin/bash
# Install the pinned Hacker Valley Media Interceptor browser worker on Ubuntu.
set -euo pipefail

INTERCEPTOR_VERSION="${INTERCEPTOR_VERSION:-1.0.1}"
INTERCEPTOR_SHA256="${INTERCEPTOR_SHA256:-e4fee0e87a724793c92a2c48b6271e5dd209573a37b767ba6d18a7d4bf4c856a}"
INTERCEPTOR_USER="${INTERCEPTOR_USER:-asm-interceptor}"
INTERCEPTOR_HOME="${INTERCEPTOR_HOME:-/var/lib/asm-interceptor}"
INTERCEPTOR_ROOT="${INTERCEPTOR_ROOT:-/opt/interceptor}"
APP_DIR="${APP_DIR:-/opt/asm}"
PROFILE="${INTERCEPTOR_PROFILE:-Default}"
DISPLAY_NUMBER="${INTERCEPTOR_DISPLAY_NUMBER:-99}"
RUN_E2E_SMOKE="${RUN_E2E_SMOKE:-1}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this installer as root." >&2
  exit 1
fi
if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
  echo "This pinned installer currently supports Linux x86_64 only." >&2
  exit 1
fi
if [ ! -d "$APP_DIR/backend/app" ] || [ ! -f "$APP_DIR/docker-compose.yml" ]; then
  echo "ASM checkout not found at $APP_DIR" >&2
  exit 1
fi

release_url="https://github.com/Hacker-Valley-Media/Interceptor/releases/download/v${INTERCEPTOR_VERSION}/Interceptor-Browser-${INTERCEPTOR_VERSION}-linux-x64.tar.gz"
release_dir="$INTERCEPTOR_ROOT/releases/$INTERCEPTOR_VERSION"
profile_root="$INTERCEPTOR_HOME/.config/BraveSoftware/Brave-Browser"
prefs="$profile_root/$PROFILE/Preferences"

echo "[1/8] Installing Brave and Xvfb"
apt-get update
apt-get install -y --no-install-recommends curl ca-certificates gnupg xvfb python3 openssl
install -d -m 0755 /usr/share/keyrings /etc/apt/sources.list.d
curl -fsS https://brave-browser-apt-release.s3.brave.com/brave-browser-archive-keyring.gpg \
  -o /usr/share/keyrings/brave-browser-archive-keyring.gpg
curl -fsS https://brave-browser-apt-release.s3.brave.com/brave-browser.sources \
  -o /etc/apt/sources.list.d/brave-browser-release.sources
apt-get update
apt-get install -y --no-install-recommends brave-browser

echo "[2/8] Creating the dedicated browser account"
if ! id "$INTERCEPTOR_USER" >/dev/null 2>&1; then
  useradd --system --create-home --home-dir "$INTERCEPTOR_HOME" \
    --shell /usr/sbin/nologin "$INTERCEPTOR_USER"
fi
install -d -m 0750 -o "$INTERCEPTOR_USER" -g "$INTERCEPTOR_USER" \
  "$INTERCEPTOR_HOME" "$INTERCEPTOR_ROOT/releases"

echo "[3/8] Downloading and verifying Interceptor v$INTERCEPTOR_VERSION"
archive="$(mktemp)"
trap 'rm -f "$archive"' EXIT
curl -fL "$release_url" -o "$archive"
printf '%s  %s\n' "$INTERCEPTOR_SHA256" "$archive" | sha256sum --check --status
rm -rf "$release_dir"
install -d -m 0755 "$release_dir"
# Official release archives wrap their payload in one versioned directory.
tar -xzf "$archive" -C "$release_dir" --strip-components=1
chown -R "$INTERCEPTOR_USER:$INTERCEPTOR_USER" "$release_dir"
ln -sfn "$release_dir" "$INTERCEPTOR_ROOT/current"
ln -sfn "$INTERCEPTOR_ROOT/current/dist/interceptor" /usr/local/bin/interceptor

echo "[4/8] Initializing a Brave profile with extension developer mode"
systemctl stop asm-interceptor-worker.service asm-interceptor-browser.service 2>/dev/null || true
set +e
runuser -u "$INTERCEPTOR_USER" -- env HOME="$INTERCEPTOR_HOME" \
  timeout 12s xvfb-run -a -s "-screen 0 1920x1080x24 -nolisten tcp" \
  /usr/bin/brave-browser \
    --user-data-dir="$profile_root" --profile-directory="$PROFILE" \
    --no-first-run --no-default-browser-check --disable-dev-shm-usage about:blank
profile_status=$?
set -e
pkill -u "$INTERCEPTOR_USER" -f brave 2>/dev/null || true
if [ "$profile_status" -ne 0 ] && [ "$profile_status" -ne 124 ]; then
  echo "Brave profile initialization failed with status $profile_status" >&2
  exit 1
fi
if [ ! -f "$prefs" ]; then
  echo "Brave did not create $prefs" >&2
  exit 1
fi
runuser -u "$INTERCEPTOR_USER" -- python3 - "$prefs" <<'PY'
import json, os, sys, tempfile
path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    data = json.load(handle)
data.setdefault("extensions", {}).setdefault("ui", {})["developer_mode"] = True
fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(path))
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    json.dump(data, handle, separators=(",", ":"))
os.replace(temp_path, path)
PY

echo "[5/8] Registering the native messaging host"
runuser -u "$INTERCEPTOR_USER" -- env HOME="$INTERCEPTOR_HOME" \
  bash "$release_dir/scripts/install.sh" \
    --browser-only --brave --profile "$PROFILE" --skip-extension

echo "[6/8] Configuring the shared worker token"
app_env="$APP_DIR/.env"
touch "$app_env"
worker_token="$(sed -n 's/^INTERCEPTOR_WORKER_TOKEN=//p' "$app_env" | tail -1)"
if [ -z "$worker_token" ]; then
  worker_token="$(openssl rand -hex 32)"
fi
WORKER_TOKEN_VALUE="$worker_token" python3 - "$app_env" <<'PY'
import os, sys
path = sys.argv[1]
key = "INTERCEPTOR_WORKER_TOKEN"
value = os.environ["WORKER_TOKEN_VALUE"]
with open(path, encoding="utf-8") as handle:
    lines = handle.read().splitlines()
out, replaced = [], False
for line in lines:
    if line.startswith(key + "="):
        if not replaced:
            out.append(f"{key}={value}")
            replaced = True
    else:
        out.append(line)
if not replaced:
    out.append(f"{key}={value}")
with open(path, "w", encoding="utf-8") as handle:
    handle.write("\n".join(out) + "\n")
PY
install -d -m 0755 /etc/asm
install -m 0600 /dev/null /etc/asm/interceptor-worker.env
cat > /etc/asm/interceptor-worker.env <<EOF
ASM_API_BASE=http://127.0.0.1:8000/api/v1
INTERCEPTOR_WORKER_TOKEN=$worker_token
INTERCEPTOR_BIN=$INTERCEPTOR_ROOT/current/dist/interceptor
PYTHONPATH=$APP_DIR/backend
PYTHONDONTWRITEBYTECODE=1
HOME=$INTERCEPTOR_HOME
EOF

echo "[7/8] Installing and starting systemd services"
cat > /etc/systemd/system/asm-interceptor-browser.service <<EOF
[Unit]
Description=ASM Interceptor browser runtime
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$INTERCEPTOR_USER
Group=$INTERCEPTOR_USER
Environment=HOME=$INTERCEPTOR_HOME
ExecStart=/usr/bin/xvfb-run -n $DISPLAY_NUMBER -s "-screen 0 1920x1080x24 -nolisten tcp" /usr/bin/brave-browser --user-data-dir=$profile_root --profile-directory=$PROFILE --load-extension=$INTERCEPTOR_ROOT/current/extension/dist --no-first-run --no-default-browser-check --disable-dev-shm-usage --disable-background-mode about:blank
Restart=always
RestartSec=3
KillMode=mixed
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/asm-interceptor-worker.service <<EOF
[Unit]
Description=ASM Interceptor recon worker
After=network-online.target docker.service asm-interceptor-browser.service
Requires=asm-interceptor-browser.service
Wants=network-online.target docker.service

[Service]
Type=simple
User=$INTERCEPTOR_USER
Group=$INTERCEPTOR_USER
WorkingDirectory=$APP_DIR/backend
EnvironmentFile=/etc/asm/interceptor-worker.env
ExecStart=/usr/bin/python3 -m app.services.interceptor_worker --kind ubuntu --worker-id ubuntu-$(hostname -s)
Restart=always
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
chmod 0600 /etc/asm/interceptor-worker.env
systemctl daemon-reload
systemctl enable asm-interceptor-browser.service asm-interceptor-worker.service
cd "$APP_DIR"
docker compose up -d --no-deps --force-recreate backend
docker compose restart nginx
systemctl restart asm-interceptor-browser.service

for attempt in $(seq 1 30); do
  if runuser -u "$INTERCEPTOR_USER" -- env HOME="$INTERCEPTOR_HOME" \
    "$INTERCEPTOR_ROOT/current/dist/interceptor" status --verbose 2>/dev/null \
    | grep -qE '^extension:[[:space:]]+reachable'; then
    break
  fi
  if [ "$attempt" -eq 30 ]; then
    journalctl -u asm-interceptor-browser.service -n 80 --no-pager >&2
    echo "Interceptor extension did not become reachable." >&2
    exit 1
  fi
  sleep 2
done
runuser -u "$INTERCEPTOR_USER" -- env HOME="$INTERCEPTOR_HOME" \
  "$INTERCEPTOR_ROOT/current/dist/interceptor" open https://example.com >/dev/null
systemctl restart asm-interceptor-worker.service

echo "[8/8] Proving queue-to-browser result delivery"
for attempt in $(seq 1 30); do
  if docker compose exec -T backend python -c \
    'from app.services.recon_jobs_service import online_kinds; raise SystemExit(0 if "ubuntu" in online_kinds() else 1)'; then
    break
  fi
  if [ "$attempt" -eq 30 ]; then
    journalctl -u asm-interceptor-worker.service -n 80 --no-pager >&2
    echo "Interceptor worker did not report ready." >&2
    exit 1
  fi
  sleep 2
done
if [ "$RUN_E2E_SMOKE" = "1" ]; then
  docker compose exec -T backend \
    python -m app.services.interceptor_smoke --target https://example.com --timeout 240
fi

echo "Interceptor v$INTERCEPTOR_VERSION is installed and ready."
