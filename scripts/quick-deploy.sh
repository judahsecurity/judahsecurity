#!/bin/bash
# =============================================================================
# ASM Platform - Quick Deploy Script
# =============================================================================
# 
# This script auto-configures and deploys the ASM platform.
# Run this on your EC2 instance after cloning the repo.
#
# Usage: ./scripts/quick-deploy.sh
# =============================================================================

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

# =============================================================================
# Auto-detect Public IP
# =============================================================================
get_public_ip() {
    # Try EC2 metadata first
    if curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/instance-id > /dev/null 2>&1; then
        PUBLIC_IP=$(curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "")
    fi
    
    # Fallback to external services
    if [ -z "${PUBLIC_IP:-}" ]; then
        PUBLIC_IP=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || \
                    curl -s --connect-timeout 5 icanhazip.com 2>/dev/null || \
                    curl -s --connect-timeout 5 ipecho.net/plain 2>/dev/null || \
                    echo "localhost")
    fi
    
    echo "$PUBLIC_IP"
}

# =============================================================================
# Create or Update .env file
# =============================================================================
setup_env() {
    log "Setting up environment..."
    
    PUBLIC_IP=$(get_public_ip)
    log "Detected public IP: $PUBLIC_IP"
    
    # Generate secrets if needed
    if [ ! -f .env ] || ! grep -q "SECRET_KEY=" .env; then
        SECRET_KEY=$(openssl rand -hex 32)
    else
        SECRET_KEY=$(grep "SECRET_KEY=" .env | cut -d'=' -f2)
    fi
    
    if [ ! -f .env ] || ! grep -q "POSTGRES_PASSWORD=" .env; then
        POSTGRES_PASSWORD=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)
    else
        POSTGRES_PASSWORD=$(grep "POSTGRES_PASSWORD=" .env | cut -d'=' -f2)
    fi
    
    # Create .env file
    cat > .env << EOF
# =============================================================================
# ASM Platform Configuration
# Auto-generated on $(date)
# =============================================================================

# Database
POSTGRES_USER=asm_user
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_DB=asm_db
DB_PORT=5432

# Backend
BACKEND_PORT=8000
SECRET_KEY=${SECRET_KEY}
DEBUG=false

# Frontend - Auto-configured with public IP
NEXT_PUBLIC_API_URL=http://${PUBLIC_IP}:8000
FRONTEND_PORT=80

# CORS - Auto-configured with public IP
CORS_ORIGINS=["http://localhost","http://localhost:80","http://localhost:3000","http://${PUBLIC_IP}","http://${PUBLIC_IP}:80","http://${PUBLIC_IP}:8000"]

# Redis
REDIS_PORT=6379

# AWS (optional - for SQS async processing)
AWS_REGION=${AWS_REGION:-us-east-1}
SQS_QUEUE_URL=${SQS_QUEUE_URL:-}
EOF
    
    chmod 600 .env
    log "Environment configured with public IP: $PUBLIC_IP"
}

# =============================================================================
# Main
# =============================================================================
main() {
    echo "=============================================="
    echo "  ASM Platform - Quick Deploy"
    echo "=============================================="
    echo
    
    # Check we're in the right directory
    if [ ! -f "docker-compose.yml" ]; then
        error "docker-compose.yml not found. Please run from the project root."
    fi
    
    # Check Docker is installed
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed. Please install Docker first."
    fi
    
    # Setup environment
    setup_env
    
    # Stop any existing containers
    log "Stopping existing containers..."
    docker compose down --remove-orphans 2>/dev/null || true
    
    # Build and start
    log "Building and starting services (this may take a few minutes)..."
    docker compose up -d --build
    
    # Wait for health checks
    log "Waiting for services to be healthy..."
    sleep 15
    
    # Check status
    echo
    docker compose ps
    echo
    
    # Get the IP again for the final message
    PUBLIC_IP=$(get_public_ip)
    
    echo "=============================================="
    echo "  Deployment Complete!"
    echo "=============================================="
    echo
    echo "Access your application:"
    echo "  - Frontend: http://${PUBLIC_IP}/"
    echo "  - API Docs: http://${PUBLIC_IP}:8000/api/docs"
    echo
    echo "Default login:"
    echo "  - Email:    admin@judahsecurity.com"
    echo "  - Password: admin123"
    echo
    echo "⚠️  Change the default password immediately!"
    echo
    echo "Useful commands:"
    echo "  - View logs:   docker compose logs -f"
    echo "  - Restart:     docker compose restart"
    echo "  - Update:      git pull && docker compose up -d --build"
    echo
}

main "$@"
