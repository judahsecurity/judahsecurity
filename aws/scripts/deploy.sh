#!/bin/bash
# =============================================================================
# ASM Platform - AWS Deployment Script
# =============================================================================
# 
# Usage:
#   ./deploy.sh [api|scanner|all] [environment]
#
# Examples:
#   ./deploy.sh all prod        # Deploy all services to production
#   PROJECT_NAME=asm-staging ./deploy.sh api staging  # Separate staging resources
#   ./deploy.sh scanner prod    # Deploy only scanner workers
# =============================================================================

set -euo pipefail

# Configuration
COMPONENT="${1:-all}"
ENVIRONMENT="${2:-prod}"
AWS_REGION="${AWS_REGION:-us-east-1}"
PROJECT_NAME="${PROJECT_NAME:-asm}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

case "${ENVIRONMENT}" in
    prod|staging|dev) ;;
    *) echo "Environment must be prod, staging, or dev" >&2; exit 1 ;;
esac
if [[ "${ENVIRONMENT}" != "prod" && "${PROJECT_NAME}" == "asm" ]]; then
    echo "Set PROJECT_NAME to the separate ${ENVIRONMENT} Terraform project name; refusing to target asm production resources" >&2
    exit 1
fi
if [[ "${ENVIRONMENT}" == "prod" && "${PROJECT_NAME}" != "asm" ]]; then
    echo "Production deployment requires PROJECT_NAME=asm" >&2
    exit 1
fi
CLUSTER="${PROJECT_NAME}-cluster"
API_SERVICE="${PROJECT_NAME}-api"
SCANNER_SERVICE="${PROJECT_NAME}-scanner"
GIT_SHA="$(git -C "${REPO_ROOT}" rev-parse --short HEAD)"
if [[ -n "$(git -C "${REPO_ROOT}" status --porcelain)" ]]; then
    echo "Deploy from a clean committed checkout; working tree has local changes" >&2
    exit 1
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
    exit 1
}

# Get AWS account ID
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

log "Deploying to AWS Account: ${AWS_ACCOUNT_ID}"
log "Region: ${AWS_REGION}"
log "Environment: ${ENVIRONMENT}"
log "Component: ${COMPONENT}"

# Login to ECR
log "Logging into ECR..."
aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${ECR_REGISTRY}

# Build and push API image
build_api() {
    log "Building API image..."
    
    docker build \
        --platform linux/amd64 \
        -t ${PROJECT_NAME}/api:latest \
        -t ${PROJECT_NAME}/api:${ENVIRONMENT}-${GIT_SHA} \
        -f "${REPO_ROOT}/backend/Dockerfile" \
        "${REPO_ROOT}/backend"
    
    # Tag for ECR
    docker tag ${PROJECT_NAME}/api:latest ${ECR_REGISTRY}/${PROJECT_NAME}/api:latest
    docker tag ${PROJECT_NAME}/api:latest ${ECR_REGISTRY}/${PROJECT_NAME}/api:${ENVIRONMENT}-${GIT_SHA}
    
    log "Pushing API image to ECR..."
    docker push ${ECR_REGISTRY}/${PROJECT_NAME}/api:latest
    docker push ${ECR_REGISTRY}/${PROJECT_NAME}/api:${ENVIRONMENT}-${GIT_SHA}
}

# Build and push Scanner image
build_scanner() {
    log "Building Scanner image..."
    
    docker build \
        --platform linux/amd64 \
        -t ${PROJECT_NAME}/scanner:latest \
        -t ${PROJECT_NAME}/scanner:${ENVIRONMENT}-${GIT_SHA} \
        -f "${REPO_ROOT}/backend/Dockerfile.scanner" \
        "${REPO_ROOT}/backend"
    
    # Tag for ECR
    docker tag ${PROJECT_NAME}/scanner:latest ${ECR_REGISTRY}/${PROJECT_NAME}/scanner:latest
    docker tag ${PROJECT_NAME}/scanner:latest ${ECR_REGISTRY}/${PROJECT_NAME}/scanner:${ENVIRONMENT}-${GIT_SHA}
    
    log "Pushing Scanner image to ECR..."
    docker push ${ECR_REGISTRY}/${PROJECT_NAME}/scanner:latest
    docker push ${ECR_REGISTRY}/${PROJECT_NAME}/scanner:${ENVIRONMENT}-${GIT_SHA}
}

# Deploy API service
check_evidence_mount() {
    local task_def efs_id
    task_def=$(aws ecs describe-services --cluster "${CLUSTER}" --services "${API_SERVICE}" \
        --query 'services[0].taskDefinition' --output text --region "${AWS_REGION}")
    [[ "${task_def}" != "None" && -n "${task_def}" ]] || error "API service ${API_SERVICE} was not found"
    efs_id=$(aws ecs describe-task-definition --task-definition "${task_def}" \
        --query 'taskDefinition.volumes[?name==`agent-evidence`].efsVolumeConfiguration.fileSystemId | [0]' \
        --output text --region "${AWS_REGION}")
    [[ "${efs_id}" != "None" && -n "${efs_id}" ]] || error "Apply the ${ENVIRONMENT} Terraform evidence volume before deploying the API"
}

deploy_api() {
    log "Deploying API service..."
    
    aws ecs update-service \
        --cluster "${CLUSTER}" \
        --service "${API_SERVICE}" \
        --force-new-deployment \
        --region ${AWS_REGION}
    
    log "Waiting for API deployment to stabilize..."
    aws ecs wait services-stable \
        --cluster "${CLUSTER}" \
        --services "${API_SERVICE}" \
        --region ${AWS_REGION}
    
    log "API deployment complete!"
}

# Deploy Scanner service
deploy_scanner() {
    log "Deploying Scanner service..."
    
    aws ecs update-service \
        --cluster "${CLUSTER}" \
        --service "${SCANNER_SERVICE}" \
        --force-new-deployment \
        --region ${AWS_REGION}
    
    log "Waiting for Scanner deployment to stabilize..."
    aws ecs wait services-stable \
        --cluster "${CLUSTER}" \
        --services "${SCANNER_SERVICE}" \
        --region ${AWS_REGION}
    
    log "Scanner deployment complete!"
}

# Run database migrations
run_migrations() {
    log "Running database migrations..."
    
    # Get task definition ARN
    TASK_DEF=$(aws ecs describe-services \
        --cluster "${CLUSTER}" \
        --services "${API_SERVICE}" \
        --query 'services[0].taskDefinition' \
        --output text \
        --region ${AWS_REGION})
    
    # Get subnets and security groups from service
    NETWORK_CONFIG=$(aws ecs describe-services \
        --cluster "${CLUSTER}" \
        --services "${API_SERVICE}" \
        --query 'services[0].networkConfiguration.awsvpcConfiguration' \
        --region ${AWS_REGION})
    
    SUBNETS=$(echo "$NETWORK_CONFIG" | jq -r '.subnets | join(",")')
    SECURITY_GROUPS=$(echo "$NETWORK_CONFIG" | jq -r '.securityGroups | join(",")')
    
    # Run migration task
    MIGRATION_TASK=$(aws ecs run-task \
        --cluster "${CLUSTER}" \
        --task-definition "${TASK_DEF}" \
        --network-configuration "awsvpcConfiguration={subnets=[${SUBNETS}],securityGroups=[${SECURITY_GROUPS}],assignPublicIp=DISABLED}" \
        --overrides '{"containerOverrides":[{"name":"api","command":["python","-m","scripts.apply_agent_ledger_migration"]}]}' \
        --query 'tasks[0].taskArn' --output text \
        --region "${AWS_REGION}")
    [[ "${MIGRATION_TASK}" != "None" && -n "${MIGRATION_TASK}" ]] || error "Migration task did not start"
    aws ecs wait tasks-stopped --cluster "${CLUSTER}" --tasks "${MIGRATION_TASK}" --region "${AWS_REGION}"
    EXIT_CODE=$(aws ecs describe-tasks --cluster "${CLUSTER}" --tasks "${MIGRATION_TASK}" \
        --query 'tasks[0].containers[?name==`api`].exitCode | [0]' --output text --region "${AWS_REGION}")
    [[ "${EXIT_CODE}" == "0" ]] || error "Agent ledger migration failed (exit ${EXIT_CODE})"
    log "Agent ledger migration complete"
}

# Main deployment logic
case ${COMPONENT} in
    api)
        check_evidence_mount
        build_api
        run_migrations
        deploy_api
        ;;
    scanner)
        build_scanner
        deploy_scanner
        ;;
    all)
        check_evidence_mount
        build_api
        build_scanner
        run_migrations
        deploy_api
        deploy_scanner
        ;;
    migrate)
        run_migrations
        ;;
    build)
        build_api
        build_scanner
        ;;
    *)
        error "Unknown component: ${COMPONENT}. Use: api, scanner, all, migrate, or build"
        ;;
esac

log "Deployment complete!"

# Print service URLs
ALB_DNS=$(aws elbv2 describe-load-balancers \
    --names ${PROJECT_NAME}-alb \
    --query 'LoadBalancers[0].DNSName' \
    --output text \
    --region ${AWS_REGION} 2>/dev/null || echo "ALB not found")

if [ "${ALB_DNS}" != "ALB not found" ]; then
    log "API is available at: http://${ALB_DNS}:8080"
    log "API Docs: http://${ALB_DNS}:8080/docs"
fi











