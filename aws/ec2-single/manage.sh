#!/bin/bash
# =============================================================================
# ASM Platform - Management Script
# =============================================================================
# 
# Usage: ./manage.sh [command]
#
# Commands:
#   start       - Start all services
#   stop        - Stop all services
#   restart     - Restart all services
#   status      - Show service status
#   logs        - Show logs (follow mode)
#   logs-api    - Show API logs only
#   logs-scan   - Show scanner logs only
#   update      - Pull latest code and restart
#   backup      - Backup database
#   restore     - Restore database from backup
#   shell       - Open shell in API container
#   db-shell    - Open PostgreSQL shell
#   init-db     - Initialize database with default users
#   refresh-intel - Pull VulnCheck KEV (community) + CISA/ENISA into disk cache
#   update-nuclei - Update Nuclei templates
#   health      - Check service health
#   ssl-setup   - Setup SSL with Let's Encrypt
#
# =============================================================================

set -euo pipefail

# Detect app directory - use script location or current directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/../../docker-compose.yml" ]; then
    APP_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
elif [ -f "./docker-compose.yml" ]; then
    APP_DIR="$(pwd)"
elif [ -d "/opt/asm" ]; then
    APP_DIR="/opt/asm"
else
    APP_DIR="$(pwd)"
fi

COMPOSE_FILE="docker-compose.yml"
if [ ! -f "$APP_DIR/$COMPOSE_FILE" ] && [ -f "$APP_DIR/docker-compose.prod.yml" ]; then
    COMPOSE_FILE="docker-compose.prod.yml"
fi
BACKUP_DIR="$APP_DIR/backups"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[i]${NC} $1"; }

cd $APP_DIR

case "${1:-help}" in
    start)
        log "Starting ASM Platform..."
        docker compose -f $COMPOSE_FILE up -d
        log "Services started"
        ;;
        
    stop)
        log "Stopping ASM Platform..."
        docker compose -f $COMPOSE_FILE down
        log "Services stopped"
        ;;
        
    restart)
        log "Restarting ASM Platform..."
        docker compose -f $COMPOSE_FILE restart
        log "Services restarted"
        ;;
        
    status)
        echo "=== Service Status ==="
        docker compose -f $COMPOSE_FILE ps
        echo
        echo "=== Resource Usage ==="
        docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"
        ;;
        
    logs)
        docker compose -f $COMPOSE_FILE logs -f --tail=100
        ;;
        
    logs-api)
        docker compose -f $COMPOSE_FILE logs -f --tail=100 backend
        ;;
        
    logs-scan)
        docker compose -f $COMPOSE_FILE logs -f --tail=100 scanner
        ;;
        
    update)
        log "Updating ASM Platform..."
        
        # Pull latest code if git repo
        if [ -d ".git" ]; then
            git pull
        fi
        
        # Rebuild and restart
        docker compose -f $COMPOSE_FILE build
        docker compose -f $COMPOSE_FILE up -d
        
        log "Update complete"
        ;;
        
    backup)
        log "Creating database backup..."
        
        mkdir -p $BACKUP_DIR
        BACKUP_FILE="$BACKUP_DIR/asm_backup_$(date +%Y%m%d_%H%M%S).sql"
        
        docker compose -f $COMPOSE_FILE exec -T db pg_dump -U asm_user asm_db > $BACKUP_FILE
        gzip $BACKUP_FILE
        
        log "Backup created: ${BACKUP_FILE}.gz"
        
        # Keep only last 7 backups
        ls -t $BACKUP_DIR/*.sql.gz 2>/dev/null | tail -n +8 | xargs -r rm
        log "Old backups cleaned up"
        ;;
        
    restore)
        if [ -z "${2:-}" ]; then
            error "Usage: ./manage.sh restore <backup_file>"
        fi
        
        BACKUP_FILE="$2"
        
        if [ ! -f "$BACKUP_FILE" ]; then
            error "Backup file not found: $BACKUP_FILE"
        fi
        
        warn "This will overwrite the current database. Are you sure? (y/n)"
        read -r response
        if [ "$response" != "y" ]; then
            log "Restore cancelled"
            exit 0
        fi
        
        log "Restoring database from $BACKUP_FILE..."
        
        # Decompress if needed
        if [[ "$BACKUP_FILE" == *.gz ]]; then
            gunzip -c "$BACKUP_FILE" | docker compose -f $COMPOSE_FILE exec -T db psql -U asm_user asm_db
        else
            docker compose -f $COMPOSE_FILE exec -T db psql -U asm_user asm_db < "$BACKUP_FILE"
        fi
        
        log "Database restored"
        ;;
        
    shell)
        docker compose -f $COMPOSE_FILE exec backend /bin/bash
        ;;
        
    db-shell)
        docker compose -f $COMPOSE_FILE exec db psql -U asm_user asm_db
        ;;
        
    init-db)
        log "Initializing database..."
        docker compose -f $COMPOSE_FILE exec backend python -m app.scripts.init_db
        log "Database initialized"
        ;;

    refresh-intel)
        log "Refreshing Vulnerability Intel caches (CISA + ENISA + VulnCheck KEV)..."
        info "First VulnCheck pull downloads the community backup; later runs only merge new rows."
        docker compose -f $COMPOSE_FILE exec -T backend python -m app.scripts.refresh_vuln_intel "${@:2}"
        log "Intel cache refresh finished — reload /vulnerability-intel"
        ;;
        
    update-nuclei)
        log "Updating Nuclei templates..."
        docker compose -f $COMPOSE_FILE exec backend nuclei -update-templates
        docker compose -f $COMPOSE_FILE exec scanner nuclei -update-templates
        log "Nuclei templates updated"
        ;;
        
    health)
        echo "=== Health Check ==="
        echo
        
        # Check containers
        echo "Container Status:"
        docker compose -f $COMPOSE_FILE ps --format "table {{.Name}}\t{{.Status}}\t{{.Health}}"
        echo
        
        # Check API health
        echo "API Health:"
        if curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/health | grep -q "200"; then
            log "API is healthy"
        else
            error "API is not responding"
        fi
        
        # Check database
        echo "Database Health:"
        if docker compose -f $COMPOSE_FILE exec -T db pg_isready -U asm_user -d asm_db > /dev/null 2>&1; then
            log "Database is healthy"
        else
            error "Database is not responding"
        fi
        
        # Check Redis
        echo "Redis Health:"
        if docker compose -f $COMPOSE_FILE exec -T redis redis-cli ping | grep -q "PONG"; then
            log "Redis is healthy"
        else
            error "Redis is not responding"
        fi
        
        # Disk usage
        echo
        echo "Disk Usage:"
        df -h / | tail -1 | awk '{print "  Used: "$3" / "$2" ("$5")"}'
        
        # Memory usage
        echo
        echo "Memory Usage:"
        free -h | grep Mem | awk '{print "  Used: "$3" / "$2}'
        ;;
        
    ssl-setup)
        if [ -z "${2:-}" ]; then
            error "Usage: ./manage.sh ssl-setup <domain> <email>"
        fi
        
        DOMAIN="$2"
        EMAIL="${3:-admin@$DOMAIN}"
        
        log "Setting up SSL for $DOMAIN..."
        
        # Install certbot
        apt-get install -y certbot
        
        # Stop nginx
        docker compose -f $COMPOSE_FILE stop nginx
        
        # Get certificate
        certbot certonly --standalone -d $DOMAIN --email $EMAIL --agree-tos --non-interactive
        
        # Copy certificates
        cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem nginx/ssl/
        cp /etc/letsencrypt/live/$DOMAIN/privkey.pem nginx/ssl/
        
        # Update nginx config
        sed -i "s/your-domain.com/$DOMAIN/g" nginx/nginx.conf
        
        # Uncomment SSL config in nginx.conf
        # (This is simplified - you may need to edit manually)
        
        # Restart nginx
        docker compose -f $COMPOSE_FILE start nginx
        
        # Setup auto-renewal
        echo "0 3 * * * certbot renew --quiet --post-hook 'docker compose -f /opt/asm/docker-compose.prod.yml restart nginx'" | crontab -
        
        log "SSL certificate installed for $DOMAIN"
        ;;
        
    help|*)
        echo "ASM Platform Management Script"
        echo
        echo "Usage: ./manage.sh [command]"
        echo
        echo "Commands:"
        echo "  start         Start all services"
        echo "  stop          Stop all services"
        echo "  restart       Restart all services"
        echo "  status        Show service status"
        echo "  logs          Show all logs (follow mode)"
        echo "  logs-api      Show API logs only"
        echo "  logs-scan     Show scanner logs only"
        echo "  update        Pull latest code and restart"
        echo "  backup        Backup database"
        echo "  restore FILE  Restore database from backup"
        echo "  shell         Open shell in API container"
        echo "  db-shell      Open PostgreSQL shell"
        echo "  init-db       Initialize database"
        echo "  refresh-intel Pull VulnCheck/CISA/ENISA intel caches"
        echo "  update-nuclei Update Nuclei templates"
        echo "  health        Check service health"
        echo "  ssl-setup     Setup SSL with Let's Encrypt"
        echo
        ;;
esac

