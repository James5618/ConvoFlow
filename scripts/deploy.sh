#!/bin/bash

# Deployment script for encrypted chat application
set -e

# Configuration
ENVIRONMENT=${1:-staging}
REGISTRY=${REGISTRY:-ghcr.io/your-org}
IMAGE_TAG=${2:-latest}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if required commands exist
    for cmd in docker kubectl helm; do
        if ! command -v $cmd &> /dev/null; then
            log_error "$cmd is not installed"
            exit 1
        fi
    done
    
    # Check if kubectl is configured
    if ! kubectl cluster-info &> /dev/null; then
        log_error "kubectl is not configured or cluster is not accessible"
        exit 1
    fi
    
    log_info "Prerequisites check passed"
}

# Deploy with Docker Compose (for on-premise)
deploy_docker_compose() {
    log_info "Deploying with Docker Compose..."
    
    export REGISTRY_URL=$REGISTRY
    export IMAGE_TAG=$IMAGE_TAG
    export ENVIRONMENT=$ENVIRONMENT
    
    # Load environment-specific variables
    if [ -f ".env.$ENVIRONMENT" ]; then
        log_info "Loading environment variables from .env.$ENVIRONMENT"
        export $(cat .env.$ENVIRONMENT | xargs)
    fi
    
    # Deploy
    docker-compose -f docker-compose.prod.yml up -d
    
    # Wait for services to be healthy
    log_info "Waiting for services to be healthy..."
    sleep 30
    
    # Check health
    if curl -f http://localhost:80/health &> /dev/null; then
        log_info "Deployment successful!"
    else
        log_error "Deployment failed - health check failed"
        exit 1
    fi
}

# Deploy to Kubernetes
deploy_kubernetes() {
    log_info "Deploying to Kubernetes..."
    
    # Create namespace if it doesn't exist
    kubectl create namespace encrypted-chat --dry-run=client -o yaml | kubectl apply -f -
    
    # Apply Kubernetes manifests with image substitution
    export IMAGE_TAG=$IMAGE_TAG
    envsubst < k8s/deployment.yaml | kubectl apply -f -
    
    # Wait for rollout to complete
    log_info "Waiting for rollout to complete..."
    kubectl rollout status deployment/encrypted-chat-backend -n encrypted-chat --timeout=300s
    kubectl rollout status deployment/encrypted-chat-frontend -n encrypted-chat --timeout=300s
    
    # Check if pods are running
    if kubectl get pods -n encrypted-chat | grep -q "Running"; then
        log_info "Kubernetes deployment successful!"
    else
        log_error "Kubernetes deployment failed"
        kubectl get pods -n encrypted-chat
        exit 1
    fi
}

# Deploy infrastructure with Terraform
deploy_infrastructure() {
    log_info "Deploying infrastructure with Terraform..."
    
    local provider=${3:-aws}
    
    cd terraform/$provider
    
    # Initialize Terraform
    terraform init
    
    # Plan deployment
    terraform plan -var-file=environments/$ENVIRONMENT.tfvars -out=tfplan
    
    # Apply if plan is successful
    if [ $? -eq 0 ]; then
        log_info "Applying Terraform plan..."
        terraform apply tfplan
        
        if [ $? -eq 0 ]; then
            log_info "Infrastructure deployment successful!"
        else
            log_error "Infrastructure deployment failed"
            exit 1
        fi
    else
        log_error "Terraform plan failed"
        exit 1
    fi
    
    cd ../..
}

# Rollback deployment
rollback() {
    log_warn "Rolling back deployment..."
    
    if command -v kubectl &> /dev/null; then
        kubectl rollout undo deployment/encrypted-chat-backend -n encrypted-chat
        kubectl rollout undo deployment/encrypted-chat-frontend -n encrypted-chat
        log_info "Kubernetes rollback completed"
    else
        # Docker Compose rollback
        docker-compose -f docker-compose.prod.yml down
        log_info "Docker Compose rollback completed"
    fi
}

# Health check
health_check() {
    log_info "Performing health check..."
    
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -f http://localhost/health &> /dev/null; then
            log_info "Health check passed"
            return 0
        fi
        
        log_info "Health check attempt $attempt/$max_attempts failed, retrying..."
        sleep 10
        ((attempt++))
    done
    
    log_error "Health check failed after $max_attempts attempts"
    return 1
}

# Cleanup old resources
cleanup() {
    log_info "Cleaning up old resources..."
    
    # Remove old Docker images
    docker image prune -f
    
    # Clean up old Kubernetes resources if applicable
    if command -v kubectl &> /dev/null; then
        kubectl delete pods -n encrypted-chat --field-selector=status.phase=Succeeded
        kubectl delete pods -n encrypted-chat --field-selector=status.phase=Failed
    fi
    
    log_info "Cleanup completed"
}

# Main deployment function
main() {
    log_info "Starting deployment for environment: $ENVIRONMENT"
    log_info "Using image tag: $IMAGE_TAG"
    
    check_prerequisites
    
    case "${DEPLOYMENT_TYPE:-kubernetes}" in
        "docker-compose")
            deploy_docker_compose
            ;;
        "kubernetes")
            deploy_kubernetes
            ;;
        "infrastructure")
            deploy_infrastructure
            ;;
        *)
            log_error "Unknown deployment type: $DEPLOYMENT_TYPE"
            log_info "Available types: docker-compose, kubernetes, infrastructure"
            exit 1
            ;;
    esac
    
    health_check
    cleanup
    
    log_info "Deployment completed successfully!"
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
