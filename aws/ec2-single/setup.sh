#!/bin/bash
# =============================================================================
# ASM Platform - Single EC2 Instance Setup Script
# =============================================================================
#
# This script sets up the ASM platform on a single EC2 instance.
# Recommended: t3.large or larger (2 vCPU, 8GB RAM minimum)
#
# Usage:
#   1. Launch an EC2 instance with Ubuntu 22.04 or Amazon Linux 2023
#   2. SSH into the instance
#   3. Clone the repository and review this script before running it
#   Or clone the repo and run: ./aws/ec2-single/setup.sh
#
# =============================================================================

set -euo pipefail

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

# =============================================================================
# System Detection
# =============================================================================

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        error "Cannot detect OS"
    fi
    log "Detected OS: $OS $VERSION"
}

# =============================================================================
# Install Dependencies
# =============================================================================

install_docker_ubuntu() {
    log "Installing Docker on Ubuntu..."
    
    # Remove old versions
    sudo apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
    
    # Install prerequisites
    sudo apt-get update
    sudo apt-get install -y \
        ca-certificates \
        curl \
        gnupg \
        lsb-release
    
    # Add Docker GPG key
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    
    # Add Docker repository
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
        $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Install Docker
    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    
    # Add current user to docker group
    sudo usermod -aG docker $USER
    
    log "Docker installed successfully"
}

install_docker_amazon_linux() {
    log "Installing Docker on Amazon Linux..."
    
    sudo yum update -y
    sudo yum install -y docker
    sudo systemctl start docker
    sudo systemctl enable docker
    sudo usermod -aG docker $USER
    
    # Install Docker Compose plugin
    sudo mkdir -p /usr/local/lib/docker/cli-plugins
    sudo curl -SL https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64 \
        -o /usr/local/lib/docker/cli-plugins/docker-compose
    sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
    
    log "Docker installed successfully"
}

install_docker() {
    if command -v docker &> /dev/null; then
        log "Docker already installed"
        return
    fi
    
    case $OS in
        ubuntu|debian)
            install_docker_ubuntu
            ;;
        amzn|amazon)
            install_docker_amazon_linux
            ;;
        *)
            error "Unsupported OS: $OS"
            ;;
    esac
}

install_tools() {
    log "Installing additional tools..."
    
    case $OS in
        ubuntu|debian)
            sudo apt-get install -y git curl wget jq htop
            ;;
        amzn|amazon)
            sudo yum install -y git curl wget jq htop
            ;;
    esac
}

# =============================================================================
# Setup Application
# =============================================================================

setup_app_directory() {
    # Use current directory if we're already in a git repo, otherwise /opt/asm
    if [ -d ".git" ] || [ -f "docker-compose.yml" ] || [ -f "docker-compose.prod.yml" ]; then
        APP_DIR="$(pwd)"
        log "Using current directory: $APP_DIR"
    else
        APP_DIR="/opt/asm"
        log "Setting up application directory: $APP_DIR"
        
        sudo mkdir -p $APP_DIR
        sudo chown $USER:$USER $APP_DIR
        
        cd $APP_DIR
    fi
    
    export APP_DIR
}

clone_or_copy_repo() {
    if [ -d ".git" ]; then
        log "Repository already exists, pulling latest..."
        git pull
    elif [ -n "${REPO_URL:-}" ]; then
        log "Cloning repository..."
        git clone $REPO_URL .
    else
        warn "No repository configured. Please copy files manually or set REPO_URL"
    fi
}

generate_secrets() {
    log "Generating secure secrets..."
    
    # Generate random passwords
    DB_PASSWORD=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 32)
    JWT_SECRET=$(openssl rand -hex 32)
    
    echo "DB_PASSWORD=$DB_PASSWORD" > .secrets
    echo "JWT_SECRET=$JWT_SECRET" >> .secrets
    chmod 600 .secrets
    
    log "Secrets generated and saved to .secrets file"
}

create_env_file() {
    log "Creating environment file..."
    
    # Load secrets
    source .secrets
    
    # Try to get SQS URL from CloudFormation or environment
    SQS_URL=""
    AWS_REGION_VAL="us-east-1"
    PUBLIC_IP=""
    
    # Check if we're on EC2 and can get metadata
    if curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/instance-id > /dev/null 2>&1; then
        # We're on EC2, try to get region
        AWS_REGION_VAL=$(curl -s http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || echo "us-east-1")
        log "Detected AWS region: $AWS_REGION_VAL"
        
        # Get public IP from EC2 metadata
        PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "")
        if [ -n "$PUBLIC_IP" ]; then
            log "Detected public IP from EC2 metadata: $PUBLIC_IP"
        fi
        
        # Try to find SQS queue from CloudFormation
        STACK_NAME=$(aws cloudformation describe-stack-resources --physical-resource-id $(curl -s http://169.254.169.254/latest/meta-data/instance-id) --query 'StackResources[0].StackName' --output text 2>/dev/null || echo "")
        if [ -n "$STACK_NAME" ] && [ "$STACK_NAME" != "None" ]; then
            SQS_URL=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --query 'Stacks[0].Outputs[?OutputKey==`SQSQueueURL`].OutputValue' --output text 2>/dev/null || echo "")
            if [ -n "$SQS_URL" ] && [ "$SQS_URL" != "None" ]; then
                log "Found SQS queue from CloudFormation: $SQS_URL"
            fi
        fi
    fi
    
    # Fallback: get public IP from external service
    if [ -z "$PUBLIC_IP" ]; then
        PUBLIC_IP=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || curl -s --connect-timeout 5 icanhazip.com 2>/dev/null || echo "localhost")
        log "Detected public IP: $PUBLIC_IP"
    fi
    
    cat > .env << EOF
# =============================================================================
# ASM Platform - Production Configuration
# Generated: $(date)
# =============================================================================

# Database Configuration
POSTGRES_USER=asm_user
POSTGRES_PASSWORD=${DB_PASSWORD}
POSTGRES_DB=asm_db
DB_PORT=5432
DATABASE_URL=postgresql://asm_user:${DB_PASSWORD}@db:5432/asm_db

# Backend Configuration
BACKEND_PORT=8000
DEBUG=false
ENVIRONMENT=production

# JWT Configuration
SECRET_KEY=${JWT_SECRET}
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# Frontend API URL (auto-configured with public IP)
NEXT_PUBLIC_API_URL=http://${PUBLIC_IP}:8000

# CORS - Auto-configured with public IP
CORS_ORIGINS=["http://localhost","http://localhost:3000","http://${PUBLIC_IP}","http://${PUBLIC_IP}:80","http://${PUBLIC_IP}:8000"]

# Redis
REDIS_URL=redis://redis:6379
REDIS_PORT=6379

# AWS SQS Configuration (for async scan processing)
# Leave empty to use database polling fallback
SQS_QUEUE_URL=${SQS_URL}
AWS_REGION=${AWS_REGION_VAL}

# Scanner Configuration
NUCLEI_TEMPLATES_PATH=/root/nuclei-templates
SCAN_OUTPUT_DIR=/app/scans

# Rate Limiting
RATE_LIMIT_PER_MINUTE=100
EOF

    chmod 600 .env
    log "Environment file created"
    
    if [ -n "$SQS_URL" ]; then
        log "SQS queue configured for async scan processing"
    else
        warn "SQS not configured - scanner will use database polling (add SQS_QUEUE_URL to .env for production)"
    fi
}

# =============================================================================
# Docker Compose Configuration
# =============================================================================

create_docker_compose() {
    log "Creating Docker Compose configuration..."
    
    cat > docker-compose.prod.yml << 'EOF'
# =============================================================================
# ASM Platform - Production Docker Compose
# Single EC2 Instance Deployment
# =============================================================================

version: '3.8'

services:
  # ===========================================================================
  # PostgreSQL Database
  # ===========================================================================
  db:
    image: postgres:15-alpine
    container_name: asm-db
    restart: unless-stopped
    environment:
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./db/init:/docker-entrypoint-initdb.d
    ports:
      - "127.0.0.1:5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - asm-network

  # ===========================================================================
  # Redis Cache
  # ===========================================================================
  redis:
    image: redis:7-alpine
    container_name: asm-redis
    restart: unless-stopped
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    ports:
      - "127.0.0.1:6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - asm-network

  # ===========================================================================
  # FastAPI Backend
  # ===========================================================================
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    container_name: asm-backend
    restart: unless-stopped
    environment:
      DATABASE_URL: ${DATABASE_URL}
      SECRET_KEY: ${SECRET_KEY}
      REDIS_URL: ${REDIS_URL}
      DEBUG: ${DEBUG}
      ENVIRONMENT: ${ENVIRONMENT}
      CORS_ORIGINS: ${CORS_ORIGINS}
      # AWS SQS for async scan job submission
      SQS_QUEUE_URL: ${SQS_QUEUE_URL:-}
      AWS_REGION: ${AWS_REGION:-us-east-1}
    volumes:
      - scan_data:/app/scans
      - nuclei_templates:/root/nuclei-templates
    ports:
      - "8000:8000"
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - asm-network
    # Required for port scanning
    cap_add:
      - NET_RAW
      - NET_ADMIN

  # ===========================================================================
  # Nginx Reverse Proxy
  # ===========================================================================
  nginx:
    image: nginx:alpine
    container_name: asm-nginx
    restart: unless-stopped
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
      - nginx_logs:/var/log/nginx
    ports:
      - "80:80"
      - "443:443"
    depends_on:
      - backend
    healthcheck:
      test: ["CMD", "nginx", "-t"]
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - asm-network

  # ===========================================================================
  # Scanner Worker (for background scans)
  # ===========================================================================
  scanner:
    build:
      context: ./backend
      dockerfile: Dockerfile.scanner
    container_name: asm-scanner
    restart: unless-stopped
    environment:
      DATABASE_URL: ${DATABASE_URL}
      REDIS_URL: ${REDIS_URL}
      WORKER_MODE: "true"
      # AWS SQS for async scan job processing
      # If not set, falls back to database polling
      SQS_QUEUE_URL: ${SQS_QUEUE_URL:-}
      AWS_REGION: ${AWS_REGION:-us-east-1}
    volumes:
      - scan_data:/app/scans
      - nuclei_templates:/root/nuclei-templates
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - asm-network
    # Required for port scanning
    cap_add:
      - NET_RAW
      - NET_ADMIN

# =============================================================================
# Volumes
# =============================================================================
volumes:
  postgres_data:
    driver: local
  redis_data:
    driver: local
  scan_data:
    driver: local
  nuclei_templates:
    driver: local
  nginx_logs:
    driver: local

# =============================================================================
# Networks
# =============================================================================
networks:
  asm-network:
    driver: bridge
EOF

    log "Docker Compose file created"
}

create_nginx_config() {
    log "Creating Nginx configuration..."
    
    mkdir -p nginx/ssl
    
    cat > nginx/nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log warn;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_conn_zone $binary_remote_addr zone=conn:10m;

    # WebSocket upgrade map — only set Connection: upgrade for WS requests
    map \$http_upgrade \$connection_upgrade {
        default upgrade;
        ''      close;
    }

    # Upstream: FastAPI backend (API + WebSocket)
    upstream api_backend {
        server localhost:8000;
        keepalive 32;
    }

    # Upstream: Next.js frontend (pages + static assets)
    upstream frontend {
        server localhost:${FRONTEND_PORT:-80};
        keepalive 16;
    }

    # HTTP - Redirect to HTTPS (uncomment when SSL is configured)
    server {
        listen 80;
        server_name _;

        # For Let's Encrypt verification
        location /.well-known/acme-challenge/ {
            root /var/www/certbot;
        }

        # Redirect to HTTPS (uncomment when SSL is ready)
        # return 301 https://\$server_name\$request_uri;

        # WebSocket: proxy directly to backend (must be BEFORE the general /api/ block)
        location /api/v1/agent/ws/ {
            proxy_pass http://api_backend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection \$connection_upgrade;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
            proxy_read_timeout 600s;
            proxy_send_timeout 600s;
        }

        # REST API: proxy directly to backend (bypasses Next.js rewrites)
        location /api/ {
            proxy_pass http://api_backend;
            proxy_http_version 1.1;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
            proxy_read_timeout 300s;
            proxy_connect_timeout 75s;
        }

        # Everything else: Next.js frontend
        location / {
            proxy_pass http://frontend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection \$connection_upgrade;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
            proxy_cache_bypass \$http_upgrade;
            proxy_read_timeout 300s;
            proxy_connect_timeout 75s;
        }
    }

    # HTTPS (uncomment and configure when SSL certificate is ready)
    # server {
    #     listen 443 ssl http2;
    #     server_name your-domain.com;
    #
    #     ssl_certificate /etc/nginx/ssl/fullchain.pem;
    #     ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    #     ssl_session_timeout 1d;
    #     ssl_session_cache shared:SSL:50m;
    #     ssl_session_tickets off;
    #
    #     ssl_protocols TLSv1.2 TLSv1.3;
    #     ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    #     ssl_prefer_server_ciphers off;
    #
    #     # HSTS
    #     add_header Strict-Transport-Security "max-age=63072000" always;
    #
    #     # WebSocket: proxy directly to backend
    #     location /api/v1/agent/ws/ {
    #         proxy_pass http://api_backend;
    #         proxy_http_version 1.1;
    #         proxy_set_header Upgrade $http_upgrade;
    #         proxy_set_header Connection $connection_upgrade;
    #         proxy_set_header Host $host;
    #         proxy_set_header X-Real-IP $remote_addr;
    #         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    #         proxy_set_header X-Forwarded-Proto $scheme;
    #         proxy_read_timeout 600s;
    #         proxy_send_timeout 600s;
    #     }
    #
    #     # REST API: proxy directly to backend
    #     location /api/ {
    #         limit_req zone=api burst=20 nodelay;
    #         limit_conn conn 10;
    #         proxy_pass http://api_backend;
    #         proxy_http_version 1.1;
    #         proxy_set_header Host $host;
    #         proxy_set_header X-Real-IP $remote_addr;
    #         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    #         proxy_set_header X-Forwarded-Proto $scheme;
    #         proxy_read_timeout 300s;
    #     }
    #
    #     # Everything else: Next.js frontend
    #     location / {
    #         proxy_pass http://frontend;
    #         proxy_http_version 1.1;
    #         proxy_set_header Upgrade $http_upgrade;
    #         proxy_set_header Connection $connection_upgrade;
    #         proxy_set_header Host $host;
    #         proxy_set_header X-Real-IP $remote_addr;
    #         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    #         proxy_set_header X-Forwarded-Proto $scheme;
    #         proxy_cache_bypass $http_upgrade;
    #         proxy_read_timeout 300s;
    #     }
    # }
}
EOF

    log "Nginx configuration created"
}

# =============================================================================
# Systemd Service
# =============================================================================

create_systemd_service() {
    log "Creating systemd service..."
    
    sudo tee /etc/systemd/system/asm.service > /dev/null << EOF
[Unit]
Description=ASM Platform
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/asm
ExecStart=/usr/bin/docker compose -f docker-compose.prod.yml up -d
ExecStop=/usr/bin/docker compose -f docker-compose.prod.yml down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable asm.service
    
    log "Systemd service created and enabled"
}

# =============================================================================
# Firewall Configuration
# =============================================================================

configure_firewall() {
    log "Configuring firewall..."
    
    if command -v ufw &> /dev/null; then
        sudo ufw allow 22/tcp    # SSH
        sudo ufw allow 80/tcp    # HTTP
        sudo ufw allow 443/tcp   # HTTPS
        sudo ufw --force enable
        log "UFW firewall configured"
    elif command -v firewall-cmd &> /dev/null; then
        sudo firewall-cmd --permanent --add-service=ssh
        sudo firewall-cmd --permanent --add-service=http
        sudo firewall-cmd --permanent --add-service=https
        sudo firewall-cmd --reload
        log "Firewalld configured"
    else
        warn "No firewall detected. Please configure manually."
    fi
}

# =============================================================================
# SSL Certificate Setup
# =============================================================================

setup_ssl_certbot() {
    read -p "Do you want to set up SSL with Let's Encrypt? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        warn "Skipping SSL setup. You can run this later."
        return
    fi
    
    read -p "Enter your domain name (e.g., asm.example.com): " DOMAIN
    read -p "Enter your email for Let's Encrypt: " EMAIL
    
    log "Installing Certbot..."
    
    case $OS in
        ubuntu|debian)
            sudo apt-get install -y certbot
            ;;
        amzn|amazon)
            sudo yum install -y certbot
            ;;
    esac
    
    # Stop nginx temporarily
    docker compose -f docker-compose.prod.yml stop nginx 2>/dev/null || true
    
    # Get certificate
    sudo certbot certonly --standalone -d $DOMAIN --email $EMAIL --agree-tos --non-interactive
    
    # Copy certificates
    sudo cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem nginx/ssl/
    sudo cp /etc/letsencrypt/live/$DOMAIN/privkey.pem nginx/ssl/
    sudo chown $USER:$USER nginx/ssl/*.pem
    
    # Update nginx config
    sed -i "s/your-domain.com/$DOMAIN/g" nginx/nginx.conf
    sed -i 's/# return 301/return 301/g' nginx/nginx.conf
    sed -i 's/# server {/server {/g' nginx/nginx.conf
    
    # Set up auto-renewal
    echo "0 3 * * * certbot renew --quiet --post-hook 'docker compose -f /opt/asm/docker-compose.prod.yml restart nginx'" | sudo crontab -
    
    log "SSL certificate installed for $DOMAIN"
}

# =============================================================================
# Initialize Database
# =============================================================================

initialize_database() {
    log "Waiting for database to be ready..."
    sleep 10
    
    log "Initializing database..."
    docker compose -f docker-compose.prod.yml exec -T backend python -m app.scripts.init_db
    
    log "Database initialized with default users"
}

# =============================================================================
# Update Nuclei Templates
# =============================================================================

update_nuclei_templates() {
    log "Updating Nuclei templates..."
    docker compose -f docker-compose.prod.yml exec -T backend nuclei -update-templates || true
    log "Nuclei templates updated"
}

# =============================================================================
# Main Installation
# =============================================================================

main() {
    echo "=============================================="
    echo "  ASM Platform - Single EC2 Setup"
    echo "=============================================="
    echo
    
    detect_os
    install_docker
    install_tools
    
    setup_app_directory
    # clone_or_copy_repo  # Uncomment if using git clone
    
    generate_secrets
    create_env_file
    create_docker_compose
    create_nginx_config
    create_systemd_service
    configure_firewall
    
    # Need to re-login for docker group
    if ! groups | grep -q docker; then
        warn "Please log out and back in, then run: cd /opt/asm && ./start.sh"
        exit 0
    fi
    
    log "Building and starting services..."
    docker compose -f docker-compose.prod.yml build
    docker compose -f docker-compose.prod.yml up -d
    
    initialize_database
    update_nuclei_templates
    
    # Optional SSL setup
    setup_ssl_certbot
    
    echo
    echo "=============================================="
    echo "  Installation Complete!"
    echo "=============================================="
    echo
    echo "Your ASM platform is now running!"
    echo
    echo "Access the API:"
    echo "  - API Docs: http://$(curl -s ifconfig.me):80/docs"
    echo "  - Health:   http://$(curl -s ifconfig.me):80/health"
    echo
    echo "Default credentials (CHANGE THESE!):"
    echo "  - Admin:   admin / changeme123"
    echo "  - Analyst: analyst / analyst123"
    echo "  - Viewer:  viewer / viewer123"
    echo
    echo "Useful commands:"
    echo "  - View logs:    docker compose -f docker-compose.prod.yml logs -f"
    echo "  - Stop:         docker compose -f docker-compose.prod.yml down"
    echo "  - Start:        docker compose -f docker-compose.prod.yml up -d"
    echo "  - Restart:      sudo systemctl restart asm"
    echo
    echo "Security reminders:"
    echo "  - Change default passwords immediately"
    echo "  - Configure SSL with Let's Encrypt"
    echo "  - Update security groups in AWS console"
    echo
}

main "$@"

