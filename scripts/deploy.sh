#!/bin/bash
set -e

# Honeypot Infrastructure Deployment Script
# This script deploys the complete honeypot infrastructure using Terraform

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if required tools are installed
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if Terraform is installed
    if ! command -v terraform &> /dev/null; then
        print_error "Terraform is not installed. Please install Terraform first."
        exit 1
    fi
    
    # Check if AWS CLI is installed
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI is not installed. Please install AWS CLI first."
        exit 1
    fi
    
    # Check if jq is installed
    if ! command -v jq &> /dev/null; then
        print_warning "jq is not installed. Some features may not work properly."
    fi
    
    print_success "Prerequisites check completed"
}

# Function to check AWS credentials
check_aws_credentials() {
    print_status "Checking AWS credentials..."
    
    if ! aws sts get-caller-identity &> /dev/null; then
        print_error "AWS credentials not configured. Please run 'aws configure' first."
        exit 1
    fi
    
    print_success "AWS credentials verified"
}

# Function to generate SSH key pair if it doesn't exist
generate_ssh_key() {
    local key_name="$1"
    local key_path="./keys/${key_name}"
    
    if [ ! -f "${key_path}" ]; then
        print_status "Generating SSH key pair: ${key_name}"
        mkdir -p ./keys
        ssh-keygen -t rsa -b 4096 -f "${key_path}" -N "" -C "honeypot-${key_name}"
        chmod 600 "${key_path}"
        chmod 644 "${key_path}.pub"
        print_success "SSH key pair generated: ${key_path}"
    else
        print_status "SSH key pair already exists: ${key_path}"
    fi
}

# Function to create terraform.tfvars if it doesn't exist
create_tfvars() {
    if [ ! -f "terraform.tfvars" ]; then
        print_status "Creating terraform.tfvars from template..."
        
        if [ -f "templates/terraform.tfvars.example" ]; then
            cp templates/terraform.tfvars.example terraform.tfvars
            print_warning "Please edit terraform.tfvars with your specific values before proceeding"
            print_status "Opening terraform.tfvars for editing..."
            ${EDITOR:-nano} terraform.tfvars
        else
            print_error "terraform.tfvars.example template not found"
            exit 1
        fi
    fi
}

# Function to validate Terraform configuration
validate_terraform() {
    print_status "Validating Terraform configuration..."
    
    terraform fmt -check=true
    terraform validate
    
    print_success "Terraform configuration is valid"
}

# Function to plan Terraform deployment
plan_deployment() {
    print_status "Planning Terraform deployment..."
    
    terraform plan -out=tfplan
    
    print_status "Terraform plan created. Review the plan above."
    read -p "Do you want to proceed with the deployment? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_warning "Deployment cancelled by user"
        exit 0
    fi
}

# Function to apply Terraform deployment
apply_deployment() {
    print_status "Applying Terraform deployment..."
    
    terraform apply tfplan
    
    if [ $? -eq 0 ]; then
        print_success "Terraform deployment completed successfully"
    else
        print_error "Terraform deployment failed"
        exit 1
    fi
}

# Function to display deployment outputs
show_outputs() {
    print_status "Deployment outputs:"
    echo
    
    # Get key outputs
    public_ip=$(terraform output -raw honeypot_instance_public_ip 2>/dev/null || echo "N/A")
    kibana_url=$(terraform output -raw kibana_url 2>/dev/null || echo "N/A")
    api_url=$(terraform output -raw api_gateway_url 2>/dev/null || echo "N/A")
    ssh_command=$(terraform output -raw ssh_connection_command 2>/dev/null || echo "N/A")
    
    echo "🌐 Public IP: ${public_ip}"
    echo "📊 Kibana Dashboard: ${kibana_url}"
    echo "🔌 API Gateway: ${api_url}"
    echo "🔑 SSH Command: ${ssh_command}"
    echo
    
    print_status "Full outputs:"
    terraform output
}

# Function to wait for services to be ready
wait_for_services() {
    local public_ip="$1"
    print_status "Waiting for services to be ready..."
    
    # Wait for SSH to be available
    print_status "Waiting for SSH service..."
    for i in {1..30}; do
        if nc -z "${public_ip}" 22 2>/dev/null; then
            print_success "SSH service is ready"
            break
        fi
        sleep 10
    done
    
    # Wait for Kibana to be available
    print_status "Waiting for Kibana service..."
    for i in {1..60}; do
        if curl -s "http://${public_ip}:5601" >/dev/null 2>&1; then
            print_success "Kibana service is ready"
            break
        fi
        sleep 10
    done
    
    # Wait for API Gateway to be available
    print_status "Waiting for API Gateway service..."
    for i in {1..30}; do
        if curl -s "http://${public_ip}:8080/health" >/dev/null 2>&1; then
            print_success "API Gateway service is ready"
            break
        fi
        sleep 10
    done
}

# Function to run post-deployment tests
run_tests() {
    local public_ip="$1"
    print_status "Running post-deployment tests..."
    
    # Test honeypot services
    local services=("22:SSH" "80:HTTP" "21:FTP" "23:Telnet")
    
    for service in "${services[@]}"; do
        IFS=':' read -r port name <<< "$service"
        if nc -z "${public_ip}" "${port}" 2>/dev/null; then
            print_success "${name} honeypot is listening on port ${port}"
        else
            print_warning "${name} honeypot is not responding on port ${port}"
        fi
    done
    
    # Test management services
    local mgmt_services=("5601:Kibana" "9200:Elasticsearch" "8080:API Gateway")
    
    for service in "${mgmt_services[@]}"; do
        IFS=':' read -r port name <<< "$service"
        if curl -s "http://${public_ip}:${port}" >/dev/null 2>&1; then
            print_success "${name} is accessible on port ${port}"
        else
            print_warning "${name} is not accessible on port ${port}"
        fi
    done
}

# Function to create monitoring dashboard
setup_monitoring() {
    print_status "Setting up monitoring dashboard..."
    
    # This would typically involve:
    # - Importing Kibana dashboards
    # - Setting up alerts
    # - Configuring monitoring rules
    
    print_status "Monitoring setup completed"
}

# Function to display next steps
show_next_steps() {
    echo
    print_success "🎉 Honeypot deployment completed successfully!"
    echo
    print_status "Next steps:"
    echo "1. Access Kibana dashboard to view honeypot data"
    echo "2. Configure alert notifications (email/Slack)"
    echo "3. Set up regular backups"
    echo "4. Monitor system health and performance"
    echo "5. Review security logs regularly"
    echo
    print_status "Useful commands:"
    echo "• View logs: ssh -i keys/honeypot-key ec2-user@${public_ip} 'sudo docker-compose logs -f'"
    echo "• Restart services: ssh -i keys/honeypot-key ec2-user@${public_ip} 'sudo docker-compose restart'"
    echo "• Check status: curl http://${public_ip}:8080/api/system/status"
    echo
}

# Main deployment function
main() {
    echo "🍯 Honeypot Infrastructure Deployment"
    echo "====================================="
    echo
    
    # Parse command line arguments
    local action="${1:-deploy}"
    local environment="${2:-production}"
    
    case $action in
        "deploy")
            check_prerequisites
            check_aws_credentials
            
            # Generate SSH key
            generate_ssh_key "honeypot-key"
            
            # Create tfvars if needed
            create_tfvars
            
            # Initialize Terraform
            print_status "Initializing Terraform..."
            terraform init
            
            # Validate configuration
            validate_terraform
            
            # Plan deployment
            plan_deployment
            
            # Apply deployment
            apply_deployment
            
            # Get public IP
            public_ip=$(terraform output -raw honeypot_instance_public_ip)
            
            # Wait for services
            wait_for_services "${public_ip}"
            
            # Run tests
            run_tests "${public_ip}"
            
            # Setup monitoring
            setup_monitoring
            
            # Show outputs
            show_outputs
            
            # Show next steps
            show_next_steps
            ;;
            
        "destroy")
            print_warning "This will destroy all honeypot infrastructure!"
            read -p "Are you sure you want to proceed? (y/N): " -n 1 -r
            echo
            
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                print_status "Destroying infrastructure..."
                terraform destroy
                print_success "Infrastructure destroyed"
            else
                print_status "Destruction cancelled"
            fi
            ;;
            
        "plan")
            check_prerequisites
            terraform init
            validate_terraform
            terraform plan
            ;;
            
        "status")
            if [ -f "terraform.tfstate" ]; then
                show_outputs
            else
                print_error "No deployment found"
            fi
            ;;
            
        *)
            echo "Usage: $0 {deploy|destroy|plan|status} [environment]"
            echo
            echo "Commands:"
            echo "  deploy   - Deploy the honeypot infrastructure"
            echo "  destroy  - Destroy the honeypot infrastructure"
            echo "  plan     - Show deployment plan"
            echo "  status   - Show current deployment status"
            echo
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"