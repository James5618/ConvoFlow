#!/bin/bash

# Cloud Infrastructure Deployment Script
# Supports both AWS and Azure deployments with automatic VM configuration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Default values
CLOUD_PROVIDER=""
ENVIRONMENT=""
DOMAIN_NAME=""
SSL_EMAIL=""
PUBLIC_KEY_PATH=""
AUTO_APPROVE=false
DESTROY=false

# Functions
print_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -c, --cloud PROVIDER     Cloud provider (aws|azure)"
    echo "  -e, --environment ENV    Environment name (dev|staging|prod)"
    echo "  -d, --domain DOMAIN      Domain name for the application"
    echo "  -s, --ssl-email EMAIL    Email for SSL certificate registration"
    echo "  -k, --key-path PATH      Path to SSH public key file"
    echo "  -y, --auto-approve       Auto approve Terraform changes"
    echo "  --destroy                Destroy infrastructure instead of creating"
    echo "  -h, --help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -c aws -e prod -d convoflow.example.com -s admin@example.com -k ~/.ssh/id_rsa.pub"
    echo "  $0 -c azure -e staging -d staging.convoflow.example.com -s ssl@example.com -k ~/.ssh/id_rsa.pub"
    echo "  $0 -c aws -e dev --destroy  # Destroy AWS dev environment"
}

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--cloud)
            CLOUD_PROVIDER="$2"
            shift 2
            ;;
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -d|--domain)
            DOMAIN_NAME="$2"
            shift 2
            ;;
        -s|--ssl-email)
            SSL_EMAIL="$2"
            shift 2
            ;;
        -k|--key-path)
            PUBLIC_KEY_PATH="$2"
            shift 2
            ;;
        -y|--auto-approve)
            AUTO_APPROVE=true
            shift
            ;;
        --destroy)
            DESTROY=true
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            ;;
    esac
done

# Validate required parameters
if [ -z "$CLOUD_PROVIDER" ]; then
    error "Cloud provider is required. Use -c or --cloud option."
fi

if [ -z "$ENVIRONMENT" ]; then
    error "Environment is required. Use -e or --environment option."
fi

if [[ "$CLOUD_PROVIDER" != "aws" && "$CLOUD_PROVIDER" != "azure" ]]; then
    error "Cloud provider must be 'aws' or 'azure'"
fi

if [[ "$ENVIRONMENT" != "dev" && "$ENVIRONMENT" != "staging" && "$ENVIRONMENT" != "prod" ]]; then
    error "Environment must be 'dev', 'staging', or 'prod'"
fi

if [ "$DESTROY" = false ]; then
    if [ -z "$DOMAIN_NAME" ]; then
        error "Domain name is required for deployment. Use -d or --domain option."
    fi

    if [ -z "$SSL_EMAIL" ]; then
        error "SSL email is required for deployment. Use -s or --ssl-email option."
    fi

    if [ -z "$PUBLIC_KEY_PATH" ]; then
        error "SSH public key path is required for deployment. Use -k or --key-path option."
    fi

    if [ ! -f "$PUBLIC_KEY_PATH" ]; then
        error "SSH public key file not found: $PUBLIC_KEY_PATH"
    fi
fi

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."

    # Check Terraform
    if ! command -v terraform &> /dev/null; then
        error "Terraform is not installed. Please install Terraform first."
    fi

    # Check cloud provider CLI
    if [ "$CLOUD_PROVIDER" = "aws" ]; then
        if ! command -v aws &> /dev/null; then
            error "AWS CLI is not installed. Please install AWS CLI first."
        fi
        
        # Check AWS credentials
        if ! aws sts get-caller-identity &> /dev/null; then
            error "AWS credentials not configured. Please run 'aws configure' first."
        fi
        
        log "AWS credentials validated"
    elif [ "$CLOUD_PROVIDER" = "azure" ]; then
        if ! command -v az &> /dev/null; then
            error "Azure CLI is not installed. Please install Azure CLI first."
        fi
        
        # Check Azure authentication
        if ! az account show &> /dev/null; then
            error "Not logged into Azure. Please run 'az login' first."
        fi
        
        log "Azure credentials validated"
    fi

    log "Prerequisites check completed"
}

# Setup Terraform backend
setup_backend() {
    log "Setting up Terraform backend..."

    local backend_config_file="${PROJECT_ROOT}/terraform/${CLOUD_PROVIDER}/backend-${ENVIRONMENT}.tfvars"
    
    if [ "$CLOUD_PROVIDER" = "aws" ]; then
        # Create S3 bucket for Terraform state (if it doesn't exist)
        local bucket_name="terraform-state-$(openssl rand -hex 8)"
        local region="us-west-2"
        
        if [ "$ENVIRONMENT" = "prod" ]; then
            bucket_name="convoflow-terraform-state-prod"
        elif [ "$ENVIRONMENT" = "staging" ]; then
            bucket_name="convoflow-terraform-state-staging"
        else
            bucket_name="convoflow-terraform-state-dev"
        fi

        info "Creating S3 bucket for Terraform state: $bucket_name"
        
        # Create bucket if it doesn't exist
        if ! aws s3api head-bucket --bucket "$bucket_name" 2>/dev/null; then
            aws s3api create-bucket \
                --bucket "$bucket_name" \
                --region "$region" \
                --create-bucket-configuration LocationConstraint="$region"
            
            # Enable versioning
            aws s3api put-bucket-versioning \
                --bucket "$bucket_name" \
                --versioning-configuration Status=Enabled
            
            # Enable encryption
            aws s3api put-bucket-encryption \
                --bucket "$bucket_name" \
                --server-side-encryption-configuration '{
                    "Rules": [{
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }]
                }'
        fi

        # Create DynamoDB table for state locking
        local table_name="terraform-state-lock-${ENVIRONMENT}"
        
        if ! aws dynamodb describe-table --table-name "$table_name" &>/dev/null; then
            info "Creating DynamoDB table for state locking: $table_name"
            aws dynamodb create-table \
                --table-name "$table_name" \
                --attribute-definitions AttributeName=LockID,AttributeType=S \
                --key-schema AttributeName=LockID,KeyType=HASH \
                --provisioned-throughput ReadCapacityUnits=1,WriteCapacityUnits=1
        fi

        # Update backend configuration in main.tf
        sed -i.bak "s|# bucket = \"your-terraform-state-bucket\"|bucket = \"$bucket_name\"|g" \
            "${PROJECT_ROOT}/terraform/aws/main.tf"
        sed -i.bak "s|# key    = \"encrypted-chat/terraform.tfstate\"|key = \"convoflow-${ENVIRONMENT}/terraform.tfstate\"|g" \
            "${PROJECT_ROOT}/terraform/aws/main.tf"
        sed -i.bak "s|# region = \"us-west-2\"|region = \"$region\"|g" \
            "${PROJECT_ROOT}/terraform/aws/main.tf"
        
        # Add DynamoDB table for locking
        sed -i.bak "s|# region = \"$region\"|region = \"$region\"\n    dynamodb_table = \"$table_name\"|g" \
            "${PROJECT_ROOT}/terraform/aws/main.tf"

    elif [ "$CLOUD_PROVIDER" = "azure" ]; then
        # Create Azure Storage Account for Terraform state
        local resource_group="terraform-state-rg"
        local storage_account="tfstate$(openssl rand -hex 4)"
        local container_name="tfstate"
        
        info "Creating Azure Storage Account for Terraform state: $storage_account"
        
        # Create resource group if it doesn't exist
        if ! az group show --name "$resource_group" &>/dev/null; then
            az group create --name "$resource_group" --location "East US"
        fi
        
        # Create storage account if it doesn't exist
        if ! az storage account show --name "$storage_account" --resource-group "$resource_group" &>/dev/null; then
            az storage account create \
                --name "$storage_account" \
                --resource-group "$resource_group" \
                --location "East US" \
                --sku Standard_LRS \
                --encryption-services blob
        fi
        
        # Get storage account key
        local account_key=$(az storage account keys list \
            --resource-group "$resource_group" \
            --account-name "$storage_account" \
            --query '[0].value' -o tsv)
        
        # Create container if it doesn't exist
        if ! az storage container show --name "$container_name" --account-name "$storage_account" --account-key "$account_key" &>/dev/null; then
            az storage container create \
                --name "$container_name" \
                --account-name "$storage_account" \
                --account-key "$account_key"
        fi

        # Update backend configuration in main.tf
        sed -i.bak "s|# resource_group_name   = \"terraform-state-rg\"|resource_group_name = \"$resource_group\"|g" \
            "${PROJECT_ROOT}/terraform/azure/main.tf"
        sed -i.bak "s|# storage_account_name  = \"terraformstatestorage\"|storage_account_name = \"$storage_account\"|g" \
            "${PROJECT_ROOT}/terraform/azure/main.tf"
        sed -i.bak "s|# container_name        = \"tfstate\"|container_name = \"$container_name\"|g" \
            "${PROJECT_ROOT}/terraform/azure/main.tf"
        sed -i.bak "s|# key                   = \"encrypted-chat/terraform.tfstate\"|key = \"convoflow-${ENVIRONMENT}/terraform.tfstate\"|g" \
            "${PROJECT_ROOT}/terraform/azure/main.tf"
    fi

    log "Terraform backend setup completed"
}

# Generate Terraform variables file
generate_tfvars() {
    log "Generating Terraform variables file..."

    local tfvars_file="${PROJECT_ROOT}/terraform/${CLOUD_PROVIDER}/${ENVIRONMENT}.tfvars"
    local public_key_content=""
    
    if [ "$DESTROY" = false ]; then
        public_key_content=$(cat "$PUBLIC_KEY_PATH")
    fi

    if [ "$CLOUD_PROVIDER" = "aws" ]; then
        cat > "$tfvars_file" << EOF
# AWS Configuration
aws_region = "us-west-2"
project_name = "convoflow"
environment = "$ENVIRONMENT"
domain_name = "$DOMAIN_NAME"
ssl_cert_email = "$SSL_EMAIL"

# Network Configuration
vpc_cidr = "10.0.0.0/16"
public_subnet_cidrs = ["10.0.1.0/24", "10.0.2.0/24"]
private_subnet_cidrs = ["10.0.3.0/24", "10.0.4.0/24"]

# EC2 Configuration
ec2_instance_type = "t3.medium"
ec2_root_volume_size = 20
public_key = "$public_key_content"
admin_cidr = "0.0.0.0/0"

# Auto Scaling Configuration
asg_min_size = 1
asg_max_size = 10
asg_desired_capacity = 2

# Database Configuration
db_instance_class = "db.t3.micro"
db_allocated_storage = 20
db_max_allocated_storage = 100
db_name = "convoflow"
db_username = "convoflow"
db_password = "$(openssl rand -base64 32)"
db_backup_retention_period = 7

# Redis Configuration
redis_node_type = "cache.t3.micro"
redis_auth_token = "$(openssl rand -base64 32)"

# DNS and SSL Configuration
manage_dns = true
enable_cloudfront = false
enable_waf = false

# Environment-specific overrides
EOF

        if [ "$ENVIRONMENT" = "prod" ]; then
            cat >> "$tfvars_file" << EOF

# Production overrides
ec2_instance_type = "t3.large"
asg_desired_capacity = 3
db_instance_class = "db.t3.small"
redis_node_type = "cache.t3.small"
enable_cloudfront = true
enable_waf = true
EOF
        elif [ "$ENVIRONMENT" = "staging" ]; then
            cat >> "$tfvars_file" << EOF

# Staging overrides
asg_desired_capacity = 2
db_instance_class = "db.t3.micro"
EOF
        fi

    elif [ "$CLOUD_PROVIDER" = "azure" ]; then
        cat > "$tfvars_file" << EOF
# Azure Configuration
azure_region = "East US"
project_name = "convoflow"
environment = "$ENVIRONMENT"
domain_name = "$DOMAIN_NAME"
ssl_cert_email = "$SSL_EMAIL"

# Network Configuration
vnet_cidr = "10.0.0.0/16"
web_subnet_cidr = "10.0.1.0/24"
db_subnet_cidr = "10.0.2.0/24"

# VM Configuration
vm_size = "Standard_B2s"
vm_instances = 2
vm_min_instances = 1
vm_max_instances = 10
public_key = "$public_key_content"
admin_cidr = "0.0.0.0/0"

# Database Configuration
db_sku_name = "B_Standard_B1ms"
db_storage_gb = 20
db_backup_retention_days = 7
db_name = "convoflow"
db_username = "convoflow"
db_password = "$(openssl rand -base64 32)"

# Redis Configuration
redis_capacity = 1
redis_family = "C"
redis_sku_name = "Standard"

# Monitoring Configuration
log_retention_days = 30

# Optional Features
enable_application_gateway = false

# Environment-specific overrides
EOF

        if [ "$ENVIRONMENT" = "prod" ]; then
            cat >> "$tfvars_file" << EOF

# Production overrides
vm_size = "Standard_B4ms"
vm_instances = 3
db_sku_name = "GP_Standard_D2s_v3"
redis_sku_name = "Premium"
redis_capacity = 1
log_retention_days = 90
enable_application_gateway = true
EOF
        elif [ "$ENVIRONMENT" = "staging" ]; then
            cat >> "$tfvars_file" << EOF

# Staging overrides
vm_size = "Standard_B2s"
vm_instances = 2
log_retention_days = 30
EOF
        fi
    fi

    log "Terraform variables file generated: $tfvars_file"
}

# Deploy or destroy infrastructure
deploy_infrastructure() {
    local terraform_dir="${PROJECT_ROOT}/terraform/${CLOUD_PROVIDER}"
    local tfvars_file="${terraform_dir}/${ENVIRONMENT}.tfvars"
    
    cd "$terraform_dir"

    if [ "$DESTROY" = true ]; then
        log "Destroying infrastructure..."
        
        if [ "$AUTO_APPROVE" = true ]; then
            terraform destroy -var-file="$tfvars_file" -auto-approve
        else
            terraform destroy -var-file="$tfvars_file"
        fi
        
        log "Infrastructure destroyed successfully!"
        return
    fi

    log "Initializing Terraform..."
    terraform init

    log "Validating Terraform configuration..."
    terraform validate

    log "Planning Terraform deployment..."
    terraform plan -var-file="$tfvars_file" -out=tfplan

    if [ "$AUTO_APPROVE" = true ]; then
        log "Applying Terraform plan..."
        terraform apply tfplan
    else
        echo ""
        warn "Review the plan above carefully!"
        read -p "Do you want to apply this plan? (yes/no): " confirm
        
        if [ "$confirm" = "yes" ]; then
            log "Applying Terraform plan..."
            terraform apply tfplan
        else
            info "Deployment cancelled by user"
            exit 0
        fi
    fi

    log "Infrastructure deployment completed!"
    
    # Display outputs
    echo ""
    log "Infrastructure Outputs:"
    terraform output
}

# Post-deployment tasks
post_deployment() {
    if [ "$DESTROY" = true ]; then
        return
    fi

    log "Running post-deployment tasks..."

    local terraform_dir="${PROJECT_ROOT}/terraform/${CLOUD_PROVIDER}"
    cd "$terraform_dir"

    # Get outputs
    if [ "$CLOUD_PROVIDER" = "aws" ]; then
        local lb_dns=$(terraform output -raw load_balancer_dns 2>/dev/null || echo "")
        local route53_ns=$(terraform output -json route53_name_servers 2>/dev/null || echo "[]")
        
        if [ -n "$lb_dns" ]; then
            info "Load Balancer DNS: $lb_dns"
            info "Application will be available at: https://$DOMAIN_NAME"
            
            if [ "$route53_ns" != "[]" ]; then
                info "Route53 Name Servers:"
                echo "$route53_ns" | jq -r '.[]' | sed 's/^/  - /'
                warn "Update your domain's name servers to the ones listed above"
            fi
        fi
        
    elif [ "$CLOUD_PROVIDER" = "azure" ]; then
        local lb_ip=$(terraform output -raw load_balancer_ip 2>/dev/null || echo "")
        
        if [ -n "$lb_ip" ]; then
            info "Load Balancer IP: $lb_ip"
            info "Application will be available at: https://$DOMAIN_NAME"
            warn "Create an A record pointing $DOMAIN_NAME to $lb_ip"
        fi
    fi

    # Wait for VMs to be ready
    info "Waiting for VMs to complete setup (this may take 5-10 minutes)..."
    sleep 60

    # Test application health
    info "Testing application health..."
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -f -s "https://$DOMAIN_NAME/health" >/dev/null 2>&1; then
            log "Application is healthy and responding!"
            break
        fi
        
        info "Attempt $attempt/$max_attempts: Application not ready yet, waiting..."
        sleep 30
        ((attempt++))
    done

    if [ $attempt -gt $max_attempts ]; then
        warn "Application health check timed out. Check the deployment manually."
    fi

    log "Post-deployment tasks completed!"
}

# Cleanup function
cleanup() {
    # Remove backup files
    find "${PROJECT_ROOT}/terraform" -name "*.tf.bak" -delete 2>/dev/null || true
}

# Main execution
main() {
    log "Starting ConvoFlow cloud infrastructure deployment"
    log "Cloud Provider: $CLOUD_PROVIDER"
    log "Environment: $ENVIRONMENT"
    
    if [ "$DESTROY" = false ]; then
        log "Domain: $DOMAIN_NAME"
        log "SSL Email: $SSL_EMAIL"
    fi

    check_prerequisites
    
    if [ "$DESTROY" = false ]; then
        setup_backend
        generate_tfvars
    fi
    
    deploy_infrastructure
    post_deployment
    cleanup

    if [ "$DESTROY" = true ]; then
        log "Infrastructure destruction completed successfully!"
    else
        log "Cloud infrastructure deployment completed successfully!"
        info "Your ConvoFlow application should be available at: https://$DOMAIN_NAME"
    fi
}

# Run main function
main "$@"
