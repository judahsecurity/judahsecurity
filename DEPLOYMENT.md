# ASM Platform - AWS Deployment Guide

<p align="center">
  <img src="frontend/public/logo.svg" alt="Judah Security Logo" width="100" height="100">
</p>

<p align="center">
  <strong>Complete guide to deploying the Attack Surface Management platform on AWS</strong>
</p>

---

## 📋 Table of Contents

- [Architecture Overview](#-architecture-overview)
- [Prerequisites](#-prerequisites)
- [Deployment Options](#-deployment-options)
  - [Option 1: CloudFormation (Recommended)](#option-1-cloudformation-recommended)
  - [Option 2: Manual EC2 Setup](#option-2-manual-ec2-setup)
- [Post-Installation](#-post-installation)
- [SSL/HTTPS Setup](#-sslhttps-setup)
- [SQS Configuration](#-sqs-configuration-optional)
- [Common Crawl S3 Index](#-common-crawl-s3-index-optional)
- [Management Commands](#-management-commands)
- [Troubleshooting](#-troubleshooting)
- [Security Hardening](#-security-hardening)
- [Cost Estimate](#-cost-estimate)
- [Cleanup](#-cleanup)

---

## 🏗️ Architecture Overview

### AWS Infrastructure Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                     AWS Cloud (us-east-1)                                    │
│                                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────────────────────┐ │
│  │                              EC2 Instance (t3.large)                                    │ │
│  │                              Ubuntu 22.04 + Docker                                      │ │
│  │                                                                                         │ │
│  │  ┌─────────────────────────────────────────────────────────────────────────────────┐   │ │
│  │  │                            Docker Compose Stack                                  │   │ │
│  │  │                                                                                  │   │ │
│  │  │   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────────┐   │   │ │
│  │  │   │   Frontend   │    │   Backend    │    │   Scanner    │    │   Redis     │   │   │ │
│  │  │   │   Next.js    │───▶│   FastAPI    │◀───│   Worker     │◀──▶│   Cache     │   │   │ │
│  │  │   │   :80        │    │   :8000      │    │              │    │   :6379     │   │   │ │
│  │  │   └──────────────┘    └──────┬───────┘    └──────┬───────┘    └─────────────┘   │   │ │
│  │  │                              │                    │                              │   │ │
│  │  │              ┌───────────────┼────────────────────┘                              │   │ │
│  │  │              │               │                                                   │   │ │
│  │  │              ▼               ▼                                                   │   │ │
│  │  │   ┌──────────────┐   ┌──────────────┐    ┌──────────────┐    ┌─────────────┐   │   │ │
│  │  │   │  PostgreSQL  │   │  Scheduler   │    │   Neo4j      │    │  AI Agent   │   │   │ │
│  │  │   │  Database    │   │ Cron Worker  │    │  (optional)  │    │ Claude/GPT  │   │   │ │
│  │  │   │   :5432      │   │              │    │  :7474,:7687 │    │ via Backend │   │   │ │
│  │  │   └──────────────┘   └──────────────┘    └──────────────┘    └─────────────┘   │   │ │
│  │  │                                                                                  │   │ │
│  │  │   ┌─────────────────────────────────────────────────────────────────────────┐   │   │ │
│  │  │   │                    Security Tools Suite                                  │   │   │ │
│  │  │   │  • Nuclei (Vulnerability Scanner)    • Masscan (Port Scanner)           │   │   │ │
│  │  │   │  • Subfinder (Subdomain Discovery)   • Nmap (Service Detection)         │   │   │ │
│  │  │   │  • HTTPX (HTTP Probing)              • EyeWitness (Screenshots)         │   │   │ │
│  │  │   │  • DNSX (DNS Resolver)               • WaybackURLs (Historical URLs)    │   │   │ │
│  │  │   │  • Naabu (Port Scanner)              • Katana (Web Crawler)             │   │   │ │
│  │  │   │  • ParamSpider (Param Finder)        • FFUF (Web Fuzzer)                │   │   │ │
│  │  │   └─────────────────────────────────────────────────────────────────────────┘   │   │ │
│  │  └──────────────────────────────────────────────────────────────────────────────────┘   │ │
│  └─────────────────────────────────────────────────────────────────────────────────────────┘ │
│                    │                                              │                          │
│                    │ Poll/Send Messages                           │ Sync Index               │
│                    ▼                                              ▼                          │
│  ┌─────────────────────────────────┐          ┌─────────────────────────────────────────┐   │
│  │          Amazon SQS             │          │              Amazon S3                   │   │
│  │   asm-scan-jobs                 │          │   asm-commoncrawl-judah              │   │
│  │                                 │          │                                          │   │
│  │   • Async scan job queue        │          │   • Common Crawl subdomain index        │   │
│  │   • Visibility: 3600s           │          │   • Historical web crawl data           │   │
│  │   • Retention: 14 days          │          │   • ~100ms subdomain lookups            │   │
│  └─────────────────────────────────┘          └─────────────────────────────────────────┘   │
│                                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────┐ │
│  │                               Security Group                                             │ │
│  │   Inbound Rules:                                                                        │ │
│  │   • SSH (22)    ─────────────  Your IP/32                                               │ │
│  │   • HTTP (80)   ─────────────  0.0.0.0/0  (Frontend)                                    │ │
│  │   • HTTPS (443) ─────────────  0.0.0.0/0  (SSL - optional)                              │ │
│  │   • TCP (8000)  ─────────────  0.0.0.0/0  (Backend API)                                 │ │
│  └─────────────────────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
                                           │
                                           │ HTTPS API Calls
                                           ▼
              ┌─────────────────────────────────────────────────────────────────┐
              │                    External APIs (Configured)                    │
              │                                                                  │
              │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
              │   │ VirusTotal  │  │   Whoxy     │  │  WhoisXML   │             │
              │   │ Subdomains  │  │ Rev. WHOIS  │  │ Netblocks/  │             │
              │   │             │  │             │  │ DNS Enrich  │             │
              │   └─────────────┘  └─────────────┘  └─────────────┘             │
              │                                                                  │
              │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
              │   │   Tracxn    │  │    crt.sh   │  │   Wayback   │             │
              │   │   M&A Data  │  │   (Free)    │  │   (Free)    │             │
              │   └─────────────┘  └─────────────┘  └─────────────┘             │
              └─────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│    User     │     │  Frontend   │     │   Backend   │     │   Scanner   │
│  (Browser)  │     │  (Next.js)  │     │  (FastAPI)  │     │  (Worker)   │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │                   │
       │  1. Login/Navigate│                   │                   │
       │──────────────────▶│                   │                   │
       │                   │  2. API Request   │                   │
       │                   │──────────────────▶│                   │
       │                   │                   │                   │
       │                   │                   │  3. Create Scan   │
       │                   │                   │   (to SQS Queue)  │
       │                   │                   │──────────────────▶│
       │                   │                   │                   │
       │                   │                   │                   │  4. Run Tools
       │                   │                   │                   │  ┌──────────┐
       │                   │                   │                   │──│  Nuclei  │
       │                   │                   │                   │  │ Subfinder│
       │                   │                   │                   │  │  Naabu   │
       │                   │                   │                   │  └──────────┘
       │                   │                   │                   │
       │                   │                   │  5. Store Results │
       │                   │                   │◀──────────────────│
       │                   │                   │                   │
       │                   │  6. Return Data   │                   │
       │                   │◀──────────────────│                   │
       │  7. Display       │                   │                   │
       │◀──────────────────│                   │                   │
```

### Component Summary

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Frontend** | Next.js 14, React 18, TypeScript, Tailwind CSS, shadcn/ui | Dashboard UI, asset explorer, scan management, agent chat |
| **Backend** | FastAPI, Python 3.11, SQLAlchemy 2.0, Pydantic v2 | REST API, authentication, business logic, 29 route modules |
| **Scanner** | Python worker + CLI tools | Async scan execution, vulnerability detection |
| **Scheduler** | Python cron worker | Recurring scan scheduling |
| **AI Agent** | LangChain, LangGraph, Anthropic Claude / OpenAI GPT | Conversational security analysis via MCP tools |
| **Database** | PostgreSQL 15 | Asset storage, findings, user management, agent conversations |
| **Graph DB** | Neo4j 5 (optional) | Asset relationship modeling, attack path analysis |
| **Cache** | Redis 7 | Session cache, job queue, rate limiting |
| **SQS** | Amazon SQS | Reliable async scan job processing |
| **S3** | Amazon S3 | Common Crawl subdomain index storage |

### AWS Resources

| Resource | Name/ID | Purpose |
|----------|---------|---------|
| **EC2 Instance** | t3.large (min), t3.xlarge (recommended) | Application host |
| **SQS Queue** | `asm-scan-jobs` | Async scan processing |
| **S3 Bucket** | `asm-commoncrawl-judah` | Subdomain index |
| **Security Group** | Ports 22, 80, 443, 8000 | Network access control |

### Docker Compose Services

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| **db** | postgres:15-alpine | 5432 | PostgreSQL database |
| **redis** | redis:7-alpine | 6379 | Cache and job queue |
| **backend** | build backend/ | 8000 | FastAPI API server |
| **frontend** | build frontend/ | 80→3000 | Next.js web UI |
| **scanner** | Dockerfile.scanner | — | Async scan worker |
| **scheduler** | Dockerfile.scanner | — | Recurring scan cron |
| **adminer** | adminer (profile: dev) | 8080 | Database admin UI |
| **neo4j** | neo4j:5-community (profile: graph) | 7474, 7687 | Graph database |

---

## 🔧 Prerequisites

Before deploying, ensure you have:

- [ ] AWS Account with appropriate permissions
- [ ] AWS CLI installed and configured (`aws configure`)
- [ ] EC2 Key Pair created in your target region
- [ ] Your public IP address (for SSH access restriction)

### Minimum Instance Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| **CPU** | 2 vCPU | 4 vCPU |
| **RAM** | 8 GB | 16 GB |
| **Storage** | 30 GB | 50 GB+ |
| **Instance Type** | t3.large | t3.xlarge |

---

## 🚀 Deployment Options

### Option 1: CloudFormation (Recommended)

The fastest way to deploy with automatic resource creation including EC2, VPC, SQS, IAM roles, and security groups.

#### Step 1: Deploy the CloudFormation Stack

```bash
aws cloudformation create-stack \
  --stack-name asm-platform \
  --template-body file://aws/ec2-single/cloudformation.yml \
  --parameters \
    ParameterKey=KeyName,ParameterValue=YOUR_KEY_PAIR_NAME \
    ParameterKey=InstanceType,ParameterValue=t3.large \
    ParameterKey=VolumeSize,ParameterValue=50 \
    ParameterKey=AllowedSSHCIDR,ParameterValue=YOUR_IP/32 \
  --capabilities CAPABILITY_IAM
```

> 💡 Replace `YOUR_KEY_PAIR_NAME` with your EC2 key pair name and `YOUR_IP/32` with your public IP (find it at https://ifconfig.me)

#### Step 2: Wait for Stack Creation

```bash
# Wait for completion (~10 minutes)
aws cloudformation wait stack-create-complete --stack-name asm-platform

# Get the outputs (Public IP, SQS URL, etc.)
aws cloudformation describe-stacks --stack-name asm-platform \
  --query 'Stacks[0].Outputs' --output table
```

#### Step 3: SSH and Complete Setup

```bash
# SSH into the instance
ssh -i your-key.pem ubuntu@PUBLIC_IP_FROM_OUTPUT

# Clone the repository
cd /opt/asm
git clone https://github.com/judahsecurity/judahsecurity.git .

# Run the setup script
chmod +x aws/ec2-single/setup.sh
./aws/ec2-single/setup.sh
```

#### What CloudFormation Creates

| Resource | Description |
|----------|-------------|
| ✅ VPC + Subnet | Isolated network with public subnet |
| ✅ EC2 Instance | Ubuntu 22.04 with Docker pre-configured |
| ✅ SQS Queue | For async scan job processing |
| ✅ IAM Role | EC2 permissions for SQS access |
| ✅ Security Group | Ports 22, 80, 443 open |
| ✅ Elastic IP | Static public IP address |
| ✅ CloudWatch Alarms | Basic monitoring |

---

### Option 2: Manual EC2 Setup

For more control over the deployment process.

#### Step 1: Launch EC2 Instance

1. Go to **EC2 Console** → **Launch Instance**
2. Configure:

| Setting | Value |
|---------|-------|
| **Name** | `asm-platform` |
| **AMI** | Ubuntu Server 22.04 LTS |
| **Instance Type** | t3.large |
| **Key Pair** | Select or create one |
| **Storage** | 50 GB gp3 |

3. **Security Group Rules:**

| Type | Port | Source |
|------|------|--------|
| SSH | 22 | Your IP/32 |
| HTTP | 80 | 0.0.0.0/0 |
| HTTPS | 443 | 0.0.0.0/0 |
| Custom TCP | 8000 | 0.0.0.0/0 |

4. Launch the instance and note the **Public IP**

#### Step 2: SSH Into Your Instance

```bash
ssh -i your-key.pem ubuntu@YOUR_EC2_PUBLIC_IP
```

#### Step 3: Install Docker

```bash
# Install Docker
curl -fsSL https://get.docker.com | sudo sh

# Add your user to the docker group
sudo usermod -aG docker $USER

# IMPORTANT: Log out and back in for group changes to take effect
exit
```

SSH back in after logging out:

```bash
ssh -i your-key.pem ubuntu@YOUR_EC2_PUBLIC_IP
```

#### Step 4: Clone the Repository

```bash
# Create application directory
sudo mkdir -p /opt/asm
sudo chown $USER:$USER /opt/asm

# Clone the repository
git clone https://github.com/judahsecurity/judahsecurity.git /opt/asm
cd /opt/asm
```

#### Step 5: Create Environment File

```bash
# Get your EC2 public IP
PUBLIC_IP=$(curl -s ifconfig.me)

# Generate secure secrets
SECRET_KEY=$(openssl rand -hex 32)
DB_PASSWORD=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)

# Create .env file
cat > .env << EOF
# =============================================================================
# ASM Platform - Production Configuration
# =============================================================================

# Database Configuration
POSTGRES_USER=asm_user
POSTGRES_PASSWORD=${DB_PASSWORD}
POSTGRES_DB=asm_db
DB_PORT=5432

# Security - KEEP THIS SECRET!
SECRET_KEY=${SECRET_KEY}

# Ports
BACKEND_PORT=8000
FRONTEND_PORT=80
REDIS_PORT=6379

# Settings
DEBUG=false

# Frontend API URL (update with your domain if using one)
NEXT_PUBLIC_API_URL=http://${PUBLIC_IP}:8000

# CORS Origins
CORS_ORIGINS=["http://localhost","http://localhost:80","http://localhost:3000","http://${PUBLIC_IP}","http://${PUBLIC_IP}:80","http://${PUBLIC_IP}:3000"]

# AWS SQS (Optional - leave empty to use database polling)
SQS_QUEUE_URL=
AWS_REGION=us-east-1

# Local LLM fallback (Ollama) — needs ~12–16 GB RAM for qwen2.5:14b.
# Use OLLAMA_MODEL=qwen2.5:7b on smaller instances. Do not open port 11434 in SG.
COMPOSE_PROFILES=ollama
OLLAMA_BASE_URL=http://ollama:11434/v1
OLLAMA_MODEL=qwen2.5:14b
OLLAMA_FALLBACK_ENABLED=true
EOF

# Secure the file
chmod 600 .env

echo "Environment file created with PUBLIC_IP: ${PUBLIC_IP}"
```

#### Step 6: Build and Start Services

```bash
# Build and start all services (this takes 10-15 minutes on first run).
# With COMPOSE_PROFILES=ollama in .env, this also starts Ollama and pulls the model
# (first model pull can take several minutes / ~9 GB for qwen2.5:14b).
sudo docker compose up -d --build

# Watch the build progress
sudo docker compose logs -f

# Confirm local LLM fallback (optional)
sudo docker compose --profile ollama logs ollama-init
curl -s http://127.0.0.1:11434/api/tags

# Press Ctrl+C to exit logs when services are running
```

#### Step 7: Verify Services Are Running

```bash
# Check all containers are running
sudo docker compose ps

# Expected output:
# NAME            STATUS
# asm_backend     Up (healthy)
# asm_frontend    Up
# asm_database    Up (healthy)
# asm_redis       Up (healthy)
# asm_scanner     Up
```

#### Step 8: Create Admin User

```bash
sudo docker exec asm_backend python -c "
from app.db.database import SessionLocal
from app.models.user import User
from app.core.security import get_password_hash

db = SessionLocal()
existing = db.query(User).filter(User.email == 'admin@judahsecurity.com').first()
if existing:
    print('Admin already exists')
else:
    admin = User(
        email='admin@judahsecurity.com',
        username='admin',
        hashed_password=get_password_hash('admin123'),
        full_name='Admin User',
        role='admin',
        is_active=True
    )
    db.add(admin)
    db.commit()
    print('Admin user created!')
db.close()
"
```

---

## ✅ Post-Installation

### Access Your Application

| Service | URL |
|---------|-----|
| **Frontend Dashboard** | `http://YOUR_EC2_IP` |
| **Backend API** | `http://YOUR_EC2_IP:8000` |
| **API Documentation** | `http://YOUR_EC2_IP:8000/api/docs` |
| **Health Check** | `http://YOUR_EC2_IP:8000/health` |

### Default Credentials

| Field | Value |
|-------|-------|
| **Email** | `admin@judahsecurity.com` |
| **Password** | `admin123` |

⚠️ **IMPORTANT: Change the default password immediately after first login!**

### Verify Everything Works

1. Open `http://YOUR_EC2_IP` in your browser
2. Login with the default credentials
3. Navigate to **Organizations** and create your first organization
4. Go to **Discovery** to start finding assets

---

## 🔒 SSL/HTTPS Setup

The repo ships with a bundled **nginx + Let's Encrypt** setup that terminates
TLS on `:443`, redirects HTTP → HTTPS, and proxies `/api/*` to the backend
and everything else to the Next.js frontend. Auto-renewal is built in.

### Option 1: Bundled nginx + Let's Encrypt (Recommended)

#### Prerequisites

1. A real **domain name** with a DNS **A record** pointing at this EC2's
   public IP. Let's Encrypt cannot issue certificates for raw IPs.
2. Security group must allow **inbound 80** and **inbound 443** from
   `0.0.0.0/0`.
3. Nothing else listening on host ports 80/443 (the frontend container is
   no longer published on `:80` once nginx is enabled).

#### Steps

```bash
cd /opt/asm

# 1. Add domain + email to .env
cat >> .env << 'EOF'
DOMAIN=your.domain.com
LETSENCRYPT_EMAIL=you@example.com
LETSENCRYPT_STAGING=0
NEXT_PUBLIC_API_URL=
CORS_ORIGINS=["https://your.domain.com"]
EOF

# 2. Pull the latest code (which includes the nginx service + bootstrap script)
git pull origin main

# 3. Rebuild the frontend so it bakes in the empty NEXT_PUBLIC_API_URL
#    (forces it to use window.location.origin in the browser)
sudo docker compose build frontend

# 4. Run the one-shot bootstrap. This:
#    - issues a dummy self-signed cert so nginx can start
#    - starts nginx, backend, frontend
#    - swaps the dummy cert for a real Let's Encrypt cert
#    - reloads nginx
sudo bash scripts/init-letsencrypt.sh
```

When it finishes you should be able to hit `https://your.domain.com` and
see a green padlock in Chrome.

> 💡 **Testing tip:** Let's Encrypt's production endpoint has strict rate
> limits (5 failures per hour per domain). While iterating, set
> `LETSENCRYPT_STAGING=1` in `.env` and run
> `sudo bash scripts/init-letsencrypt.sh --force`. The cert won't be
> trusted by browsers, but you can confirm the dance works. Then flip back
> to `0` and re-run with `--force` for the real cert.

#### What the bundled setup does

| Component | Role |
|-----------|------|
| `nginx` (in `docker-compose.yml`) | Terminates TLS on `:443`, redirects HTTP → HTTPS, proxies `/api/*` and `/health` / `/docs` to backend, everything else to frontend. Auto-reloads every 6h to pick up renewed certs. |
| `certbot` (in `docker-compose.yml`) | Long-running container that runs `certbot renew` every 12h. |
| `nginx/templates/app.conf.template` | Templated nginx config; `${DOMAIN}` is substituted at container start via envsubst. |
| `scripts/init-letsencrypt.sh` | One-shot bootstrap — handles the chicken-and-egg problem of needing a cert before nginx can start. |
| Volumes `letsencrypt_certs`, `letsencrypt_www` | Shared cert storage and ACME HTTP-01 webroot. |

#### Common issues

- **`Connection refused` on :443** — the security group is still missing
  port 443. Open it.
- **`DNS problem: NXDOMAIN looking up A for your.domain.com`** — DNS isn't
  pointed at this server yet. Wait for propagation
  (`dig +short your.domain.com` should return the EC2's public IP).
- **Browser still says "Not Secure"** — you're hitting `http://` or the
  raw IP. Always use `https://your.domain.com`. Hard-refresh
  (`Cmd+Shift+R`) to drop any cached HSTS preload from earlier sessions.
- **Backend calls 404 / CORS error** — `NEXT_PUBLIC_API_URL` was set
  to a non-empty value when the frontend was built. Set it to empty in
  `.env`, then `sudo docker compose build frontend && sudo docker compose up -d frontend`.

### Option 2: AWS Certificate Manager + ALB

For production deployments where you want AWS-managed certs (no renewal
on the box) and a real load balancer in front:

1. Request a public certificate in **ACM** (us-east-1 if you also want
   CloudFront).
2. Create an **Application Load Balancer** with an HTTPS:443 listener
   using that ACM cert.
3. Two target groups against your EC2 instance:
   - `/*` → port `80` (frontend) — but only if you re-enable the
     frontend port publish in `docker-compose.yml`. Easier path: keep
     the bundled nginx and target port 80 → nginx → frontend.
   - Alternatively, drop the bundled nginx entirely and target port
     `3000` (frontend) and `8000` (backend) directly with path-based
     routing on the ALB.
4. Tighten the EC2 security group so only the ALB SG can reach
   `:80` / `:3000` / `:8000`.
5. Point your DNS at the ALB's DNS name (CNAME or Route 53 A-ALIAS).

### Option 3: CloudFront in front of HTTP origin

Cheapest if traffic is low — also gets you a CDN for free.

1. Request an ACM cert in **us-east-1** for your domain.
2. Create a CloudFront distribution with that cert; origin = your EC2's
   public DNS, origin protocol = HTTP, origin port = 80.
3. Forward all headers / cookies / query strings (this app is dynamic).
4. Point your DNS at the CloudFront domain.

---

## 📬 SQS Configuration (Optional)

For reliable async scan processing in production:

### Create SQS Queue

```bash
aws sqs create-queue \
  --queue-name asm-scan-jobs \
  --attributes VisibilityTimeout=3600,MessageRetentionPeriod=1209600
```

### Add to Environment

```bash
# Get the queue URL
SQS_URL=$(aws sqs get-queue-url --queue-name asm-scan-jobs --query 'QueueUrl' --output text)

# Add to .env
echo "SQS_QUEUE_URL=${SQS_URL}" >> /opt/asm/.env
echo "AWS_REGION=us-east-1" >> /opt/asm/.env

# Restart services
cd /opt/asm
sudo docker compose down && sudo docker compose up -d
```

### Verify SQS Connection

```bash
# Check scanner logs for SQS connection
sudo docker compose logs scanner | grep -i sqs

# Should show: "SQS client initialized for queue: https://sqs..."
```

---

## 🕸️ Common Crawl S3 Index (Optional)

For faster subdomain discovery using historical web crawl data:

### Setup

```bash
cd /opt/asm/aws/commoncrawl

# Create S3 bucket
chmod +x setup-s3.sh
./setup-s3.sh asm-commoncrawl-yourorg us-east-1

# Build initial index (takes 10-30 minutes)
pip install boto3 httpx
python update-index.py --bucket asm-commoncrawl-yourorg

# Add to environment
echo "CC_S3_BUCKET=asm-commoncrawl-yourorg" >> /opt/asm/.env

# Restart services
cd /opt/asm
sudo docker compose down && sudo docker compose up -d
```

### Benefits

- **Speed**: ~100ms lookups vs 30-60s API queries
- **Historical data**: Find forgotten/legacy subdomains
- **Offline capable**: Works even if Common Crawl API is down

---

## 📤 Push updates to your AWS instance

After you change code and push to your repo, update the running app on AWS.

### On EC2 (single instance with Docker Compose)

From your **local machine**, push to git; then on the **EC2 instance**:

```bash
# SSH into the instance
ssh -i your-key.pem ubuntu@YOUR_EC2_PUBLIC_IP

# Go to app directory
cd /opt/asm

# Pull latest code (use your repo URL if different)
git pull origin main

# Rebuild and restart all services (picks up code + dependency changes)
sudo docker compose up -d --build

# Optional: restart only backend + scanner if you only changed Python
# sudo docker compose up -d --build backend scanner
```

To **pull from a different branch** (e.g. `develop`):

```bash
git fetch origin
git checkout develop
git pull origin develop
sudo docker compose up -d --build
```

### Using ECS (deploy script)

If you deploy with ECS and the deploy script:

```bash
# From your local machine, in the repo root
cd aws/scripts
chmod +x deploy.sh

# Build images, push to ECR, and update ECS services
./deploy.sh all prod

# Or only API or only scanner
./deploy.sh api prod
./deploy.sh scanner prod
```

Requires: AWS CLI configured, ECR repo and ECS cluster already set up (see deploy script and ECS docs).

### Optional environment variables (new in recent updates)

You can add these to `.env` on the instance if you use the features; the app runs without them.

| Variable | Purpose |
|----------|---------|
| `TAVILY_API_KEY` | Agent web search (CVE/exploit research). Get key at [tavily.com](https://tavily.com). |
| `AGENT_TOOL_OUTPUT_MAX_CHARS` | Max characters of tool output sent to the agent (default 20000). |
| `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD` | Neo4j graph (attack surface relationships). |

WhatWeb (technology enrichment) runs if the **whatweb** CLI is installed in the backend/scanner image; otherwise technology scans use Wappalyzer only. No env var required.

---

## 🛠️ Management Commands

### Viewing Logs

```bash
cd /opt/asm

# All services
sudo docker compose logs -f

# Specific service
sudo docker compose logs -f backend
sudo docker compose logs -f frontend
sudo docker compose logs -f scanner
sudo docker compose logs -f db
```

### Service Management

```bash
cd /opt/asm

# Check status
sudo docker compose ps

# Restart all services
sudo docker compose restart

# Restart specific service
sudo docker compose restart backend

# Stop all services
sudo docker compose down

# Start all services
sudo docker compose up -d

# Rebuild and restart (after code changes)
sudo docker compose up -d --build
```

### Database Operations

```bash
# Access PostgreSQL shell
sudo docker exec -it asm_database psql -U asm_user -d asm_db

# Backup database
sudo docker exec asm_database pg_dump -U asm_user asm_db > backup_$(date +%Y%m%d).sql

# Restore database
cat backup.sql | sudo docker exec -i asm_database psql -U asm_user -d asm_db
```

### Container Shell Access

```bash
# Backend shell
sudo docker exec -it asm_backend bash

# Scanner shell
sudo docker exec -it asm_scanner bash

# Redis CLI
sudo docker exec -it asm_redis redis-cli
```

### Update Nuclei Templates

```bash
sudo docker exec asm_scanner nuclei -update-templates
```

---

## 🔍 Troubleshooting

### Container Not Starting

```bash
# Check container logs
sudo docker compose logs backend

# Check if ports are in use
sudo netstat -tlnp | grep -E '80|8000|5432|6379'

# Restart Docker
sudo systemctl restart docker
```

### Database Connection Issues

```bash
# Check database is running
sudo docker compose ps db

# Test database connection
sudo docker exec asm_database psql -U asm_user -d asm_db -c "SELECT 1"

# Check database logs
sudo docker compose logs db
```

### Findings Page: "column vulnerabilities.is_manual does not exist"

If the Findings page shows a database error and backend logs say `column vulnerabilities.is_manual does not exist`, the `vulnerabilities` table is missing columns added by a migration. Run the migration once on the server:

```bash
cd /opt/asm
sudo docker exec asm_backend python scripts/migrate_add_manual_finding_fields.py
```

Then reload the Findings page. No need to restart containers.

```bash
# Check scanner status
sudo docker compose ps scanner

# View scanner logs
sudo docker compose logs --tail=100 scanner

# Check SQS configuration
sudo docker compose exec scanner env | grep SQS

# Restart scanner
sudo docker compose restart scanner
```

### Frontend Not Loading

```bash
# Check frontend logs
sudo docker compose logs frontend

# Verify NEXT_PUBLIC_API_URL in .env matches your server
grep NEXT_PUBLIC_API_URL .env

# Rebuild frontend with correct URL
sudo docker compose up -d --build frontend
```

### 504 Gateway Timeout (Agent)

If the Agent page shows **504** when you send a message, the reverse proxy (nginx, ALB, or CDN) in front of the backend is closing the connection before the agent finishes. Agent requests can take several minutes (LLM + tools). Increase the proxy timeout:

- **Nginx:** In the `location` that proxies to the backend, set `proxy_read_timeout 300s;` (and optionally `proxy_connect_timeout` / `proxy_send_timeout`). Reload nginx.
- **AWS ALB:** In the load balancer attributes, set **Idle timeout** to 300 seconds (or higher). Default is 60.
- See [ENV_EXAMPLE.md](ENV_EXAMPLE.md) → "Troubleshooting: 504 Gateway Timeout" for details and CLI examples.

### "No such container" Error

```bash
# List all containers
sudo docker ps -a

# If containers don't exist, start them
sudo docker compose up -d

# If Docker isn't running
sudo systemctl start docker
```

### Permission Denied for Port Scanning

The scanner container needs `NET_RAW` capability. Verify in `docker-compose.yml`:

```yaml
scanner:
  cap_add:
    - NET_RAW
    - NET_ADMIN
```

---

## 🔐 Security Hardening

### Immediate Actions

- [ ] **Change default admin password** - Do this first!
- [ ] **Restrict SSH access** - Only allow your IP in security group
- [ ] **Generate new SECRET_KEY** - `openssl rand -hex 32`
- [ ] **Set DEBUG=false** - Already set if you followed this guide

### Production Recommendations

- [ ] **Enable HTTPS** - Use Let's Encrypt or ACM
- [ ] **Use IAM roles** - Instead of access keys for AWS services
- [ ] **Enable CloudTrail** - For audit logging
- [ ] **Set up VPC Flow Logs** - For network monitoring
- [ ] **Regular updates** - `sudo apt update && sudo apt upgrade -y`
- [ ] **Backup database** - Set up automated backups
- [ ] **Monitor resources** - Set up CloudWatch alarms

### Security Group Best Practices

| Port | Access |
|------|--------|
| 22 (SSH) | Your IP only |
| 80 (HTTP) | 0.0.0.0/0 (redirect to HTTPS) |
| 443 (HTTPS) | 0.0.0.0/0 |
| 8000 (API) | Internal only or via ALB |
| 5432 (PostgreSQL) | Internal only |
| 6379 (Redis) | Internal only |

---

## 💰 Cost Estimate

### Monthly Costs (us-east-1)

| Component | Specification | Monthly Cost |
|-----------|---------------|--------------|
| EC2 | t3.large (2 vCPU, 8GB RAM) | ~$60 |
| EBS | 50GB gp3 | ~$5 |
| Elastic IP | 1 | ~$4 |
| SQS | ~10,000 requests | ~$0.01 |
| Data Transfer | ~50GB out | ~$5 |
| **Total** | | **~$75/month** |

### Cost Optimization Tips

- Use **Reserved Instances** for 30-60% savings
- Use **Spot Instances** for non-production
- Schedule instance stop during off-hours
- Use **t3.medium** for light usage

---

## 🧹 Cleanup

### Delete CloudFormation Stack

```bash
aws cloudformation delete-stack --stack-name asm-platform
aws cloudformation wait stack-delete-complete --stack-name asm-platform
```

### Manual Cleanup

```bash
# Stop and remove containers
cd /opt/asm
sudo docker compose down -v

# Remove images
sudo docker system prune -a -f

# Remove application directory
sudo rm -rf /opt/asm
```

### AWS Resources to Delete

1. ☐ EC2 Instance
2. ☐ EBS Volumes
3. ☐ Elastic IP
4. ☐ SQS Queue
5. ☐ Security Groups
6. ☐ IAM Roles
7. ☐ S3 Buckets (if using Common Crawl)

---

## 📚 Additional Resources

- [Main README](README.md) - Full feature documentation
- [AWS EC2 Single Instance Guide](aws/ec2-single/README.md) - Detailed EC2 setup
- [Common Crawl Setup](aws/commoncrawl/README.md) - S3 index configuration
- [API Documentation](http://YOUR_IP:8000/api/docs) - Interactive API docs

---

## 🆘 Getting Help

If you encounter issues:

1. Check the [Troubleshooting](#-troubleshooting) section
2. Review container logs: `sudo docker compose logs -f`
3. Verify environment variables: `cat .env`
4. Check service health: `sudo docker compose ps`

---

<p align="center">
  <strong>Made with ❤️ by Judah Security</strong>
</p>

