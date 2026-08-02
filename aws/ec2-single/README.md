# ASM Platform - Single EC2 Instance Deployment

The simplest way to run the ASM platform on AWS. All components run on a single EC2 instance using Docker Compose with optional SQS for async scan job processing.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         EC2 Instance (t3.large)                          │
│                                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐ │
│  │ Frontend │  │ Backend  │  │  Redis   │  │ Scanner  │  │PostgreSQL │ │
│  │ Next.js  │──│ FastAPI  │──│  Cache   │  │  Worker  │──│    DB     │ │
│  │  :3000   │  │  :8000   │  │  :6379   │  │          │  │   :5432   │ │
│  └──────────┘  └────┬─────┘  └──────────┘  └────┬─────┘  └───────────┘ │
│                     │                           │                        │
│                     │      ┌────────────────────┘                       │
│                     │      │                                             │
│                     ▼      ▼                                             │
│            ┌─────────────────────┐                                      │
│            │   Security Tools    │                                      │
│            │  Nuclei, Subfinder  │                                      │
│            │  HTTPX, Naabu, etc. │                                      │
│            └─────────────────────┘                                      │
│                     │                                                    │
└─────────────────────┼────────────────────────────────────────────────────┘
                      │
              ┌───────┴───────┐
              │   AWS SQS     │  (Optional - for async scans)
              │  Scan Queue   │
              └───────────────┘
```

## Cost Estimate

| Component | Specification | Monthly Cost |
|-----------|--------------|--------------|
| EC2 | t3.large (2 vCPU, 8GB RAM) | ~$60 |
| EBS | 50GB gp3 | ~$5 |
| Elastic IP | 1 | ~$4 |
| SQS | ~10,000 requests | ~$0.01 |
| Data Transfer | ~50GB out | ~$5 |
| **Total** | | **~$75/month** |

*Costs based on us-east-1. Use Reserved Instances or Spot for savings.*

---

## Deployment Options

### Option 1: CloudFormation (Recommended)

This creates everything automatically: EC2, VPC, SQS queue, IAM roles, security groups.

```bash
# Deploy the stack
aws cloudformation create-stack \
  --stack-name asm-platform \
  --template-body file://aws/ec2-single/cloudformation.yml \
  --parameters \
    ParameterKey=KeyName,ParameterValue=your-key-pair \
    ParameterKey=InstanceType,ParameterValue=t3.large \
    ParameterKey=VolumeSize,ParameterValue=50 \
    ParameterKey=AllowedSSHCIDR,ParameterValue=YOUR_IP/32 \
  --capabilities CAPABILITY_IAM

# Wait for completion (~10 minutes)
aws cloudformation wait stack-create-complete --stack-name asm-platform

# Get outputs (Public IP, SQS URL, etc.)
aws cloudformation describe-stacks --stack-name asm-platform \
  --query 'Stacks[0].Outputs' --output table
```

#### CloudFormation Creates:
- ✅ VPC with public subnet
- ✅ EC2 instance with Ubuntu 22.04
- ✅ SQS queue for scan jobs
- ✅ IAM role with SQS permissions
- ✅ Security group (SSH, HTTP, HTTPS)
- ✅ Elastic IP
- ✅ CloudWatch alarms

### Option 2: Manual EC2 Setup

1. **Launch EC2 Instance**
   - AMI: Ubuntu 22.04 LTS (`ami-0c7217cdde317cfec` in us-east-1)
   - Instance Type: t3.large (minimum)
   - Storage: 50GB gp3
   - Security Group: Allow ports 22, 80, 443

2. **Create SQS Queue (Optional but recommended)**
   ```bash
   aws sqs create-queue \
     --queue-name asm-scan-jobs \
     --attributes VisibilityTimeout=3600,MessageRetentionPeriod=1209600
   ```

3. **Create IAM Role for EC2**
   - Attach `AmazonSQSFullAccess` policy (or create custom policy)
   - Attach role to EC2 instance

---

## Installation

### Step 1: SSH into your EC2 instance

```bash
ssh -i your-key.pem ubuntu@YOUR_PUBLIC_IP
```

### Step 2: Clone the repository

```bash
git clone https://github.com/judahsecurity/judahsecurity.git /opt/asm
cd /opt/asm
```

### Step 3: Run the setup script

```bash
chmod +x aws/ec2-single/setup.sh
./aws/ec2-single/setup.sh
```

This will:
- Install Docker and Docker Compose
- Generate secure passwords
- Create environment file with SQS configuration
- Build and start all containers
- Initialize the database
- Update Nuclei templates

### Step 4: Configure SQS (if using CloudFormation)

The CloudFormation template automatically adds SQS configuration to `.env`. Verify:

```bash
cat /opt/asm/.env | grep SQS
# Should show:
# SQS_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/123456789/asm-platform-scan-jobs
# AWS_REGION=us-east-1
```

If you created SQS manually, add these to `.env`:

```bash
# Add to /opt/asm/.env
SQS_QUEUE_URL=https://sqs.YOUR_REGION.amazonaws.com/YOUR_ACCOUNT_ID/asm-scan-jobs
AWS_REGION=us-east-1
```

Then restart the services:
```bash
docker compose -f docker-compose.prod.yml down
docker compose -f docker-compose.prod.yml up -d
```

---

## How Scan Jobs Work

### With SQS (Production - Recommended)

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   User      │     │   Backend   │     │    SQS      │     │   Scanner   │
│ Creates Scan│────▶│ Submits Job │────▶│   Queue     │────▶│   Worker    │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
                                                                   │
                                                                   ▼
                                                            ┌─────────────┐
                                                            │ Runs Nuclei │
                                                            │ Port Scans  │
                                                            │ Discovery   │
                                                            └─────────────┘
```

**Benefits:**
- Reliable message delivery
- Automatic retries
- Visibility timeout for long scans
- Decoupled architecture

### Without SQS (Fallback Mode)

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   User      │     │   Backend   │     │   Scanner   │
│ Creates Scan│────▶│ Saves to DB │◀────│ Polls DB    │
│             │     │ (PENDING)   │     │ Every 20s   │
└─────────────┘     └─────────────┘     └─────────────┘
```

The scanner worker automatically falls back to database polling if SQS is not configured.

---

## Environment Variables

### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection | `postgresql://user:pass@db:5432/asm_db` |
| `SECRET_KEY` | JWT signing key | `openssl rand -hex 32` |
| `REDIS_URL` | Redis connection | `redis://redis:6379/0` |

### AWS/SQS (Optional)

| Variable | Description | Example |
|----------|-------------|---------|
| `SQS_QUEUE_URL` | SQS queue URL | `https://sqs.us-east-1.amazonaws.com/123456789/queue-name` |
| `AWS_REGION` | AWS region | `us-east-1` |
| `AWS_ACCESS_KEY_ID` | IAM access key | Only if not using IAM role |
| `AWS_SECRET_ACCESS_KEY` | IAM secret key | Only if not using IAM role |

**Note:** When running on EC2 with an IAM role attached, you don't need AWS credentials - the SDK uses the instance role automatically.

---

## Post-Installation

### Access the Platform

| Service | URL |
|---------|-----|
| Frontend | `http://YOUR_IP` |
| API | `http://YOUR_IP:8000` |
| API Docs | `http://YOUR_IP:8000/api/docs` |

### Default Credentials

| User | Password | Role |
|------|----------|------|
| admin@judahsecurity.com | admin123 | Admin |

⚠️ **Change the password immediately!**

### Verify SQS Connection

```bash
# Check scanner logs
docker compose logs scanner | grep -i sqs

# Should show:
# INFO - SQS client initialized for queue: https://sqs...

# If SQS not configured, you'll see:
# WARNING - SQS_QUEUE_URL not set, running in test mode
```

### Create a Test Scan

```bash
# Login and get token
TOKEN=$(curl -s -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin@judahsecurity.com&password=admin123" \
  | jq -r '.access_token')

# Create a scan
curl -X POST "http://localhost:8000/api/v1/scans/" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Scan",
    "organization_id": 1,
    "scan_type": "VULNERABILITY",
    "targets": ["example.com"]
  }'

# Check scan status
curl "http://localhost:8000/api/v1/scans/" \
  -H "Authorization: Bearer $TOKEN" | jq
```

---

## Management Commands

```bash
cd /opt/asm

# View all container status
docker compose -f docker-compose.prod.yml ps

# View logs
docker compose -f docker-compose.prod.yml logs -f
docker compose -f docker-compose.prod.yml logs -f scanner
docker compose -f docker-compose.prod.yml logs -f backend

# Restart services
docker compose -f docker-compose.prod.yml restart

# Restart just the scanner
docker compose -f docker-compose.prod.yml restart scanner

# Update and redeploy
git pull
docker compose -f docker-compose.prod.yml up -d --build

# Backup database
docker compose -f docker-compose.prod.yml exec db pg_dump -U asm_user asm_db > backup.sql

# Update Nuclei templates
docker compose -f docker-compose.prod.yml exec scanner nuclei -update-templates
```

---

## SSL/HTTPS Setup

### Option 1: Let's Encrypt (Free)

```bash
# Install certbot
sudo apt install certbot

# Stop services temporarily
docker compose -f docker-compose.prod.yml stop

# Get certificate
sudo certbot certonly --standalone -d your-domain.com

# Copy certificates
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem /opt/asm/nginx/ssl/
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem /opt/asm/nginx/ssl/

# Restart services
docker compose -f docker-compose.prod.yml up -d
```

### Option 2: AWS Certificate Manager + ALB

For production with custom domains, use an Application Load Balancer with ACM certificate.

---

## Troubleshooting

### Scanner stuck on "SQS not set"

```bash
# Check environment
docker compose -f docker-compose.prod.yml exec scanner env | grep SQS

# If empty, add to .env and restart
echo "SQS_QUEUE_URL=your-queue-url" >> .env
docker compose -f docker-compose.prod.yml up -d
```

### Scans staying in PENDING status

```bash
# Check scanner is running
docker compose -f docker-compose.prod.yml ps scanner

# Check scanner logs for errors
docker compose -f docker-compose.prod.yml logs --tail=50 scanner

# Check if scanner can reach targets (network issues)
docker compose -f docker-compose.prod.yml exec scanner ping -c 3 example.com
```

### Permission denied for port scanning

The scanner container needs `NET_RAW` capability. Verify in docker-compose:

```yaml
scanner:
  cap_add:
    - NET_RAW
```

### Database connection issues

```bash
# Check database is running
docker compose -f docker-compose.prod.yml ps db

# Check database logs
docker compose -f docker-compose.prod.yml logs db

# Test connection
docker compose -f docker-compose.prod.yml exec db psql -U asm_user -d asm_db -c "SELECT 1"
```

---

## Cleanup

### Delete CloudFormation Stack

```bash
aws cloudformation delete-stack --stack-name asm-platform
aws cloudformation wait stack-delete-complete --stack-name asm-platform
```

### Manual Cleanup

1. Terminate EC2 instance
2. Delete EBS volumes
3. Release Elastic IP
4. Delete SQS queue
5. Delete security groups
6. Delete IAM role

---

## Security Hardening

1. **Restrict SSH** to your IP only
2. **Change default passwords** immediately
3. **Enable HTTPS** with SSL certificates
4. **Use IAM roles** instead of access keys
5. **Enable CloudTrail** for audit logging
6. **Set up VPC Flow Logs** for network monitoring
7. **Regular updates**: `sudo apt update && sudo apt upgrade -y`



