# The Force Security - Attack Surface Management

<p align="center">
  <img src="frontend/public/logo.svg" alt="The Force Security Logo" width="120" height="120" style="filter: invert(1);">
</p>

<p align="center">
  <strong>A comprehensive Attack Surface Management (ASM) platform for security teams to discover, monitor, and manage their organization's external attack surface.</strong>
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-architecture">Architecture</a> •
  <a href="#-aws-deployment">AWS Deployment</a> •
  <a href="#-api-endpoints">API Docs</a>
</p>

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                                Docker Compose                                     │
├──────────────────────────────────────────────────────────────────────────────────┤
│                                                                                   │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐      │
│  │   Frontend   │   │   Backend    │   │  PostgreSQL  │   │    Redis     │      │
│  │  (Next.js)   │──▶│  (FastAPI)   │──▶│   Database   │   │  Cache/Queue │      │
│  │   Port 80    │   │  Port 8000   │   │  Port 5432   │   │  Port 6379   │      │
│  └──────────────┘   └──────┬───────┘   └──────────────┘   └──────────────┘      │
│                            │                                                      │
│         ┌──────────────────┼──────────────────┐                                  │
│         │                  │                  │                                    │
│         ▼                  ▼                  ▼                                    │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐      │
│  │   Scanner    │   │  Scheduler   │   │   AI Agent   │   │   Neo4j      │      │
│  │  (Worker)    │   │ (Cron Worker)│   │ Claude / GPT │   │  (Graph DB)  │      │
│  │              │   │              │   │  LangGraph   │   │  Port 7474   │      │
│  └──────┬───────┘   └──────────────┘   └──────┬───────┘   └──────────────┘      │
│         │                                      │                                  │
│         ▼                                      ▼                                  │
│  ┌──────────────────────────────────┐   ┌──────────────────────────────────┐     │
│  │      Security Tools Suite       │   │         MCP Tool Server          │     │
│  │  • Nuclei (Vuln Scanner)        │   │  • Agent-accessible scan tools   │     │
│  │  • Subfinder (Subdomains)       │   │  • Discovery, recon, analysis    │     │
│  │  • HTTPX (HTTP Probing)         │   │  • Remediation guidance          │     │
│  │  • DNSX (DNS Toolkit)           │   └──────────────────────────────────┘     │
│  │  • Naabu (Port Scanner)         │                                             │
│  │  • Masscan (Mass Scanner)       │                                             │
│  │  • Katana (Web Crawler)         │                                             │
│  │  • EyeWitness (Screenshots)     │                                             │
│  │  • WaybackURLs (Historical)     │                                             │
│  │  • ParamSpider (Param Finder)   │                                             │
│  └──────────────────────────────────┘                                             │
│                                                                                   │
└──────────────────────────────────────────────────────────────────────────────────┘

External autonomous pentester (optional):

┌────────────────────────────┐     POST /api/v1/ingest/*      ┌──────────────────┐
│  Aegis Vanguard            │ ─────────────────────────────▶ │  ASM Platform    │
│  (aegis-vanguard/)         │                                │  findings +      │
│  ReACT recon → vuln →      │ ◀── on-demand validate_finding │  validations     │
│  exploit → report          │                                │                  │
└────────────────────────────┘                                └──────────────────┘
```

## ✨ Features

### 🖥️ Modern Dashboard
- **Real-time Metrics**: Security overview with vulnerability counts, asset stats, and risk indicators
- **World Map Visualization**: Geographic distribution of assets with geolocation enrichment
- **Remediation Efficiency**: Track MTTR (Mean Time to Remediate) and vulnerability exposure trends
- **Quick Actions**: One-click access to scans, discovery, and enrichment operations

### 📦 Asset Management
- **Comprehensive Asset Inventory**: Track domains, subdomains, IPs, and web applications
- **Asset Risk Scoring (ARS)**: 0-100 risk score based on vulnerabilities and exposure
- **Asset Criticality Score (ACS)**: 0-10 criticality rating with customizable drivers
- **Open Ports & Services**: Detailed port information with service detection
- **Technology Detection**: Identify web technologies, frameworks, and versions
- **Geolocation Enrichment**: Multiple providers (ip-api, ipinfo, WhoisXML)
- **Labeling System**: Organize assets with custom labels for targeted scanning

### 🔍 Discovery & Reconnaissance
- **Subdomain Enumeration**: Automated discovery using multiple sources
- **DNS Enrichment**: A, AAAA, MX, NS, TXT, SOA records via WhoisXML API
- **CIDR/Netblock Discovery**: Find IP ranges by organization name
- **Domain Validation**: Automatic detection of parked, suspicious, or privacy-protected domains
- **Certificate Transparency**: Discover domains via SSL/TLS certificate logs
- **TLDFinder (optional)**: [ProjectDiscovery tldfinder](https://github.com/projectdiscovery/tldfinder) for better TLD/domain coverage; enable `use_tldfinder` in full discovery or run a dedicated **tldfinder** scan. See [docs/MCP_AND_TLDFINDER.md](docs/MCP_AND_TLDFINDER.md).

### 🏢 Inventory Management
Unified inventory page with three tabs:

| Tab | Description |
|-----|-------------|
| **CIDR Blocks** | Manage IP ranges and netblocks with scope controls |
| **Domains** | Domain inventory with validation status and DNS enrichment |
| **M&A** | Track acquisitions and discover domains from acquired companies |

### 🤝 M&A / Acquisitions Tracking
- **Tracxn Integration**: Import acquisition history automatically
- **Domain Discovery**: Find domains associated with acquired companies
- **Integration Status**: Track merger/acquisition integration progress
- **Asset Linking**: Connect discovered assets to their acquisition source

### 🔒 Vulnerability Management
- **Nuclei Scanning**: 8000+ vulnerability templates
- **Severity-based Sorting**: Critical → High → Medium → Low → Info
- **Vulnerability Details**: CVSS scores, remediation guidance, detection timeline
- **Port Scanning**: Masscan + Nmap for comprehensive service discovery
- **Finding Tracking**: First seen, last seen, resurfaced dates
- **Finding Exceptions**: Track accepted risks and false positives with justifications
- **MITRE ATT&CK Enrichment**: Map findings to MITRE techniques and CWEs

### 🤖 AI Security Agent
- **Conversational Interface**: Chat-based security analysis powered by Claude or GPT
- **MCP Tool Integration**: Agent can run scans, discover assets, and analyze findings through natural language
- **Playbook Library**: Pre-built playbooks for common recon and analysis workflows
- **Dual Mode**: "Assist" mode (requires approval for actions) or "Agent" mode (autonomous)
- **WebSocket Streaming**: Real-time status updates during tool execution
- **Knowledge Base**: Persistent agent notes and knowledge for context across sessions

### 🕸️ Graph Visualization & Attack Paths
- **Neo4j Integration**: Asset relationship modeling (Domain → Subdomain → IP → Port → Service → Technology → Vulnerability → CVE)
- **Attack Path Analysis**: Discover how vulnerabilities chain across infrastructure
- **Attack Surface Overview**: Risk distribution, discovery sources, technology breakdown (PostgreSQL fallback when Neo4j is unavailable)
- **Relationship Explorer**: Visual graph of asset connections and co-hosted services

### 📊 Remediation Management
- **Remediation Playbooks**: Auto-generated guidance based on CWE and vulnerability type
- **Progress Tracking**: Track remediation status across findings
- **CWE Database**: Built-in weakness classification and mitigation advice

### 📅 Scheduled Scanning
Automated recurring scans with flexible frequencies:

| Frequency | Use Case |
|-----------|----------|
| Every 15 minutes | Critical port monitoring |
| Every 30 minutes | High-priority asset checks |
| Hourly | Active vulnerability detection |
| Daily | Comprehensive security scans |
| Weekly | Full discovery sweeps |

### 📸 Screenshots & Visual Recon
- **EyeWitness Integration**: Automated web application screenshots
- **Gallery View**: Browse screenshots with filtering and search
- **Scheduled Captures**: Automatic periodic screenshots

### 🌐 External Discovery Sources

| Source | Description | API Key |
|--------|-------------|---------|
| **Certificate Transparency (crt.sh)** | SSL/TLS certificate logs | ❌ Free |
| **Wayback Machine** | Historical URLs and subdomains | ❌ Free |
| **RapidDNS** | DNS enumeration | ❌ Free |
| **Microsoft 365** | Federated domain discovery | ❌ Free |
| **Common Crawl** | Web archive subdomain discovery | ❌ Free |
| **AlienVault OTX** | Threat intelligence passive DNS | ✅ Free tier |
| **VirusTotal** | Subdomain database | ✅ Paid |
| **WhoisXML API** | IP ranges, DNS records | ✅ Paid |
| **Whoxy** | Reverse WHOIS by email | ✅ Paid |
| **Tracxn** | M&A/Acquisition data | ✅ Paid |

### 🛡️ Security Tools Integration

| Tool | Purpose | Use Case |
|------|---------|----------|
| **Nuclei** | Vulnerability scanner | CVE detection, misconfiguration |
| **Subfinder** | Subdomain discovery | Passive enumeration |
| **HTTPX** | HTTP probing | Web server detection |
| **DNSX** | DNS toolkit | DNS resolution |
| **Naabu** | Port scanner | Service discovery |
| **Masscan** | Mass port scanner | Large-scale scanning |
| **Nmap** | Service detection | Port/service fingerprinting |
| **Katana** | Web crawler | URL and endpoint discovery |
| **EyeWitness** | Screenshot capture | Visual reconnaissance |
| **WaybackURLs** | Historical URLs | Attack surface history |
| **ParamSpider** | Parameter finder | URL parameter discovery |
| **Amass** | Asset discovery | Advanced enumeration |
| **MassDNS** | DNS resolver | Bulk DNS queries |
| **FFUF** | Web fuzzer | Directory/file brute-forcing |
| **TLDFinder** | TLD discovery | ProjectDiscovery TLD coverage |

## 🛠️ Tech Stack

| Layer | Technology |
|-------|------------|
| **Frontend** | Next.js 14, React 18, TypeScript, Tailwind CSS, shadcn/ui (Radix) |
| **State Management** | Zustand, TanStack React Query, Axios |
| **Backend** | Python 3.11, FastAPI, SQLAlchemy 2.0, Pydantic v2 |
| **Database** | PostgreSQL 15 |
| **Graph Database** | Neo4j 5 (optional, for relationship modeling) |
| **Cache / Queue** | Redis 7 |
| **Auth** | JWT (python-jose), bcrypt, OAuth2 password flow |
| **AI Agent** | LangChain, LangGraph, Anthropic Claude / OpenAI GPT |
| **Container** | Docker, Docker Compose |
| **Cloud** | AWS (EC2, SQS, S3) |

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose installed
- Git
- 30GB+ disk space (recommended)

### 1. Clone the Repository

```bash
# Create directory and clone
sudo mkdir -p /opt/asm
sudo chown $USER:$USER /opt/asm
git clone https://github.com/javrav2/theforcesecurity_ASM.git /opt/asm
cd /opt/asm
```

### 2. Create Environment File

```bash
cat > .env << 'EOF'
# Database
POSTGRES_USER=asm_user
POSTGRES_PASSWORD=your_secure_password_here
POSTGRES_DB=asm_db

# Security - Generate with: openssl rand -hex 32
SECRET_KEY=your_64_character_secret_key_here

# Ports
BACKEND_PORT=8000
FRONTEND_PORT=80
DB_PORT=5432
REDIS_PORT=6379

# Settings
DEBUG=false
EOF
```

### 3. Build and Start Services

```bash
# Build and start all services
sudo docker compose up -d --build

# Watch the build progress
sudo docker compose logs -f
```

### 4. Create Admin User

```bash
sudo docker exec -it asm_backend python -c "
from app.db.database import SessionLocal
from app.models.user import User
from app.core.security import get_password_hash

db = SessionLocal()
existing = db.query(User).filter(User.email == 'admin@theforce.security').first()
if existing:
    print('Admin already exists')
else:
    admin = User(
        email='admin@theforce.security',
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

### 5. Access the Application

| Service | URL |
|---------|-----|
| **Frontend Dashboard** | `http://localhost` |
| **Backend API** | `http://localhost:8000` |
| **API Documentation** | `http://localhost:8000/api/docs` |
| **MCP (agent tools)** | `GET/POST /api/v1/mcp/tools`, `/api/v1/mcp/call` — see [MCP & TLDFinder](docs/MCP_AND_TLDFINDER.md) |

**Default Login:**
- Username: `admin`
- Password: `admin123`

⚠️ **Change the default password immediately!**

## ⚙️ Configuring API Keys

Configure external service API keys in **Settings**:

1. Navigate to **Settings** in the sidebar
2. Select your organization
3. Configure API keys:

| Service | Purpose | Get Key |
|---------|---------|---------|
| **VirusTotal** | Subdomain discovery | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| **WhoisXML API** | IP ranges, DNS enrichment | [whoisxmlapi.com](https://whoisxmlapi.com/) |
| **AlienVault OTX** | Threat intelligence | [otx.alienvault.com](https://otx.alienvault.com/api) |
| **Whoxy** | Reverse WHOIS | [whoxy.com](https://www.whoxy.com/) |
| **Tracxn** | M&A data | [platform.tracxn.com](https://platform.tracxn.com/) |

4. For **WhoisXML**: Add organization names to discover IP ranges
5. For **Whoxy**: Add registration emails to discover domains

## ☁️ AWS Deployment

### Quick Deploy with CloudFormation

```bash
# Deploy the stack
aws cloudformation create-stack \
  --stack-name asm-platform \
  --template-body file://aws/ec2-single/cloudformation.yml \
  --parameters \
    ParameterKey=KeyName,ParameterValue=your-key-pair \
    ParameterKey=InstanceType,ParameterValue=t3.large \
    ParameterKey=AllowedSSHCIDR,ParameterValue=YOUR_IP/32 \
  --capabilities CAPABILITY_IAM

# Wait for completion (~10 minutes)
aws cloudformation wait stack-create-complete --stack-name asm-platform

# Get outputs
aws cloudformation describe-stacks --stack-name asm-platform \
  --query 'Stacks[0].Outputs' --output table

# SSH and complete setup
ssh -i your-key.pem ubuntu@<PUBLIC_IP>
cd /opt/asm
git clone https://github.com/javrav2/theforcesecurity_ASM.git .
./aws/ec2-single/setup.sh
```

### Manual AWS Setup (Existing EC2)

```bash
# SSH into your EC2 instance
ssh -i your-key.pem ubuntu@YOUR_EC2_IP

# Create and setup directory
sudo mkdir -p /opt/asm
sudo chown $USER:$USER /opt/asm
cd /opt/asm

# Clone repository
git clone https://github.com/javrav2/theforcesecurity_ASM.git .

# Create .env file (update PUBLIC_IP with your EC2 IP)
PUBLIC_IP=$(curl -s ifconfig.me)
cat > .env << EOF
POSTGRES_USER=asm_user
POSTGRES_PASSWORD=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)
POSTGRES_DB=asm_db
SECRET_KEY=$(openssl rand -hex 32)
BACKEND_PORT=8000
FRONTEND_PORT=80
DEBUG=false
NEXT_PUBLIC_API_URL=http://${PUBLIC_IP}:8000
CORS_ORIGINS=["http://localhost","http://${PUBLIC_IP}","http://${PUBLIC_IP}:80"]
SQS_QUEUE_URL=
AWS_REGION=us-east-1
EOF

# Build and start
sudo docker compose up -d --build

# Check status
sudo docker compose ps
```

### Updating Code on AWS (push your changes)

**1. Push code to your Git remote** (so the EC2 or CI can pull it):

```bash
git add -A
git commit -m "Your message"
git push origin main   # or your branch, e.g. origin master
```

If you use **AWS CodeCommit** (in addition to or instead of GitHub):

```bash
# One-time: add CodeCommit as remote (replace region and repo name)
git remote add aws https://git-codecommit.us-east-1.amazonaws.com/v1/repos/theforcesecurity_ASM
# Push to AWS
git push aws main
```

**Push from your machine:** Run `git push origin main` (or `git push aws main`) in your own terminal or Cursor terminal so your GitHub/CodeCommit credentials or SSH keys are used. If push fails with "could not read Username", use SSH: `git remote set-url origin git@github.com:javrav2/theforcesecurity_ASM.git` then push again (requires [SSH key](https://docs.github.com/en/authentication/connecting-to-github-with-ssh) added to GitHub).

**2. On the EC2 instance** (single-instance / Docker Compose):

```bash
ssh -i your-key.pem ubuntu@YOUR_EC2_IP
cd /opt/asm
git pull
sudo docker compose up -d --build --force-recreate
```

**Alternative: ECR + ECS**  
If you deploy with ECS and the `aws/scripts/deploy.sh` script, from your **local machine** (after pushing code to Git):

```bash
cd /path/to/theforcesecurity_ASM/aws/scripts
./deploy.sh all prod   # builds images, pushes to ECR, updates ECS services
```

Requires ECR repositories and ECS cluster (`asm-cluster`, etc.) already set up.

For optional env vars (e.g. `TAVILY_API_KEY`, `AGENT_TOOL_OUTPUT_MAX_CHARS`) and the full **Push updates to your AWS instance** checklist, see [DEPLOYMENT.md#push-updates-to-your-aws-instance](DEPLOYMENT.md#-push-updates-to-your-aws-instance). See [DEPLOYMENT.md](DEPLOYMENT.md) for full AWS deployment instructions.

## 📁 Project Structure

```
theforcesecurity_ASM/
├── frontend/                    # Next.js 14 Frontend
│   ├── src/
│   │   ├── app/                # 21 pages (dashboard, assets, agent, graph, etc.)
│   │   ├── components/         # UI components (shadcn/ui + custom)
│   │   ├── lib/               # API client (api.ts), utilities
│   │   └── store/             # Zustand state management
│   ├── public/                # Static assets, logo
│   ├── Dockerfile
│   └── package.json
│
├── backend/                    # FastAPI Backend
│   ├── app/
│   │   ├── api/routes/        # 29 API route modules
│   │   ├── models/            # 20 database models
│   │   ├── schemas/           # Pydantic v2 schemas
│   │   ├── services/          # 55+ services (incl. agent/, mcp/)
│   │   └── workers/           # Background workers (scanner, scheduler)
│   ├── scripts/               # Database migrations
│   ├── Dockerfile             # Backend + security tools
│   ├── Dockerfile.scanner     # Scanner worker image
│   └── requirements.txt
│
├── aegis-vanguard/            # Aegis Vanguard: autonomous ReACT pentest agent
│   ├── agent/                 # Orchestrator, recon/vuln/exploit/report agents, guardrails
│   ├── run_pentest.py         # Full pentest entrypoint
│   ├── validate_finding.py    # On-demand single-finding validator
│   ├── asm_bridge.py          # Ingestion client → ASM platform
│   └── DEPLOYMENT.md          # Standalone / Docker deployment guide
│
├── harness/                   # Aegis Harness: batch scanning + detection benchmarking
│   └── local_harness/         # batch/ (run many targets) + benchmark/ (accuracy vs corpus)
│
├── db/init/                   # Database initialization
├── docs/                      # Technical documentation (11 guides)
├── aws/                       # AWS deployment configs
│   ├── cloudformation/        # CloudFormation templates
│   ├── terraform/            # Terraform IaC
│   ├── ec2-single/           # Single EC2 setup
│   ├── commoncrawl/          # S3 index setup
│   └── sni-ip-ranges/        # SNI discovery data
│
├── docker-compose.yml         # Container orchestration (7 services)
├── APPLICATION_MAP.md         # Visual architecture & data flow map
├── DEPLOYMENT.md             # AWS deployment guide
├── ENV_EXAMPLE.md            # Environment variable reference
├── Makefile                  # Development commands
└── README.md
```

## 📊 API Endpoints

All endpoints are prefixed with `/api/v1/`. Full interactive docs available at `/api/docs`.

### Core APIs

| Category | Endpoints | Description |
|----------|-----------|-------------|
| **Auth** | `/auth/login`, `/auth/me`, `/auth/logout`, `/auth/refresh` | JWT authentication |
| **Users** | `/users/` | User CRUD and role management |
| **Organizations** | `/organizations/` | Multi-tenant org management |
| **Assets** | `/assets/`, `/assets/{id}`, `/assets/enrich-geolocation` | Asset CRUD + enrichment |
| **Vulnerabilities** | `/vulnerabilities/`, `/vulnerabilities/stats/*` | Findings + analytics |
| **Scans** | `/scans/`, `/scans/by-label`, `/scans/{id}/cancel` | Scan management |
| **Schedules** | `/scan-schedules/` | Automated recurring scans |
| **Scan Config** | `/scan-config/` | Scan configuration profiles |

### Discovery APIs

| Endpoint | Description |
|----------|-------------|
| `/discovery/run` | Subdomain discovery (Subfinder, crt.sh, etc.) |
| `/external-discovery/run` | External source discovery (VT, Whoxy, OTX, etc.) |
| `/external-discovery/enrich-dns` | DNS record enrichment (WhoisXML) |
| `/external-discovery/validate-domains` | Domain validation (parked, suspicious) |
| `/netblocks/discover` | CIDR discovery by org name |
| `/sni-discovery/` | SNI-based asset discovery |

### Inventory APIs

| Endpoint | Description |
|----------|-------------|
| `/netblocks/` | CIDR block management |
| `/acquisitions/` | M&A tracking |
| `/acquisitions/import-from-tracxn` | Tracxn import |
| `/acquisitions/{id}/discover-domains` | Domain discovery for M&A |
| `/labels/` | Asset labeling and organization |

### AI Agent APIs

| Endpoint | Description |
|----------|-------------|
| `/agent/status` | Agent availability and config |
| `/agent/query` | Send query to AI agent (REST) |
| `/agent/ws/{sessionId}` | WebSocket streaming for agent |
| `/agent/conversations` | Conversation history |
| `/agent/approve`, `/agent/answer` | Approval and Q&A flows |
| `/agent-knowledge/` | Agent knowledge base CRUD |
| `/mcp/tools`, `/mcp/call` | MCP tool listing and invocation |

### Aegis Vanguard / Ingestion APIs

External agent auth uses `tfasm_` API keys (`agent_type: aegis_vanguard`). See [aegis-vanguard/README.md](aegis-vanguard/README.md).

| Endpoint | Description |
|----------|-------------|
| `/ingest/findings` | Batch findings from Aegis Vanguard (API key) |
| `/ingest/heartbeat` | Agent health check |
| `/ingest/api-keys` | Create / list / revoke agent API keys (JWT) |
| `/vulnerabilities/{id}/validate` | Queue on-demand Aegis Vanguard finding validation |

### Security & Analysis APIs

| Endpoint | Description |
|----------|-------------|
| `/nuclei/` | Nuclei vulnerability scans |
| `/ports/` | Port scan results |
| `/screenshots/` | Screenshot management |
| `/waybackurls/` | Historical URL fetching |
| `/remediation/` | Remediation playbooks and CWE info |
| `/exceptions/` | Finding exceptions management |
| `/github-secrets/` | GitHub secret scanning |
| `/mitre/` | MITRE ATT&CK enrichment |
| `/reports/` | PDF/HTML report generation |

### Graph APIs

| Endpoint | Description |
|----------|-------------|
| `/graph/status` | Neo4j connection status |
| `/graph/sync` | Sync PostgreSQL data to Neo4j |
| `/graph/relationships` | Query asset relationships |
| `/graph/attack-paths` | Attack path analysis |
| `/graph/fallback/*` | PostgreSQL-based attack surface overview |

### Utility APIs

| Endpoint | Description |
|----------|-------------|
| `/tools/status` | Security tool availability check |
| `/app-structure/` | Application structure discovery |

## 🔧 Useful Commands

All commands should be run from the application directory (`/opt/asm` on AWS):

```bash
# Navigate to app directory (AWS)
cd /opt/asm

# View logs
sudo docker compose logs -f
sudo docker compose logs -f backend

# Restart services
sudo docker compose restart

# Rebuild and restart (after code changes)
git pull && sudo docker compose up -d --build --force-recreate

# Access backend shell
sudo docker exec -it asm_backend bash

# Access database
sudo docker exec -it asm_database psql -U asm_user -d asm_db

# Update Nuclei templates
sudo docker exec asm_scanner nuclei -update-templates

# Clean up
sudo docker compose down -v
sudo docker system prune -a -f
```

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [APPLICATION_MAP.md](APPLICATION_MAP.md) | Visual architecture, data flow, and database schema diagrams |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Complete AWS deployment guide (CloudFormation, EC2, SSL) |
| [ENV_EXAMPLE.md](ENV_EXAMPLE.md) | Environment variable reference and troubleshooting |
| [docs/RECON_WORKFLOW.md](docs/RECON_WORKFLOW.md) | Full reconnaissance pipeline (5 phases) |
| [docs/GRAPH_SCHEMA.md](docs/GRAPH_SCHEMA.md) | Neo4j graph database schema and queries |
| [docs/MCP_AND_TLDFINDER.md](docs/MCP_AND_TLDFINDER.md) | MCP tool server and TLDFinder setup |
| [docs/SCAN_TYPES_AND_PROJECT_SETTINGS.md](docs/SCAN_TYPES_AND_PROJECT_SETTINGS.md) | Scan type configuration |
| [docs/SCAN_EXECUTION_AND_RESULTS.md](docs/SCAN_EXECUTION_AND_RESULTS.md) | Scan execution flow and result handling |
| [docs/SCAN_TROUBLESHOOTING.md](docs/SCAN_TROUBLESHOOTING.md) | Common scan issues and fixes |
| [docs/ADHOC_AND_RECURRING_SCANS.md](docs/ADHOC_AND_RECURRING_SCANS.md) | Ad-hoc vs scheduled scan workflows |
| [docs/GRAPH_AND_DATA_FLOW_ROADMAP.md](docs/GRAPH_AND_DATA_FLOW_ROADMAP.md) | Graph feature roadmap |

## 🔒 Security Considerations

1. **Change default passwords** immediately after deployment
2. **Generate a secure SECRET_KEY**: `openssl rand -hex 32`
3. **Use HTTPS** in production (configure reverse proxy with SSL)
4. **Restrict CORS origins** to your frontend domain
5. **Enable DEBUG=false** in production
6. **Keep Nuclei templates updated** regularly
7. **Restrict security groups** to necessary IPs only
8. **Regular backups** of PostgreSQL data

## 📄 License

MIT License - See LICENSE file for details.

## 🙏 Acknowledgments

- [ProjectDiscovery](https://github.com/projectdiscovery) for Nuclei and security tools
- [tomnomnom](https://github.com/tomnomnom/waybackurls) for waybackurls
- [RedSiege](https://github.com/RedSiege) for EyeWitness
- [shadcn/ui](https://ui.shadcn.com/) for React components
- [crt.sh](https://crt.sh) for certificate transparency data
- [WhoisXML API](https://whoisxmlapi.com/) for DNS and WHOIS data
- [Tracxn](https://tracxn.com/) for M&A intelligence

---

<p align="center">
  <strong>Made with ❤️ by The Force Security</strong>
</p>
