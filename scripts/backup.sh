#!/bin/bash
set -e

# Honeypot Backup Script
# This script creates backups of Elasticsearch data and configuration

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

# Configuration
BACKUP_DIR="/opt/honeypot/backups"
S3_BUCKET=$(terraform output -raw backup_bucket_name 2>/dev/null || echo "")
ELASTICSEARCH_URL="http://localhost:9200"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="honeypot_backup_${DATE}"

# Function to create local backup directory
create_backup_dir() {
    print_status "Creating backup directory..."
    sudo mkdir -p "${BACKUP_DIR}/${BACKUP_NAME}"
    sudo chown $(whoami):$(whoami) "${BACKUP_DIR}/${BACKUP_NAME}"
}

# Function to backup Elasticsearch indices
backup_elasticsearch() {
    print_status "Backing up Elasticsearch indices..."
    
    local backup_path="${BACKUP_DIR}/${BACKUP_NAME}/elasticsearch"
    mkdir -p "${backup_path}"
    
    # Get list of indices
    local indices=$(curl -s "${ELASTICSEARCH_URL}/_cat/indices/honeypot-*?h=index" | tr '\n' ',' | sed 's/,$//')
    
    if [ -n "$indices" ]; then
        # Create snapshot repository
        curl -X PUT "${ELASTICSEARCH_URL}/_snapshot/backup_repo" \
            -H 'Content-Type: application/json' \
            -d "{
                \"type\": \"fs\",
                \"settings\": {
                    \"location\": \"${backup_path}\"
                }
            }"
        
        # Create snapshot
        curl -X PUT "${ELASTICSEARCH_URL}/_snapshot/backup_repo/${BACKUP_NAME}" \
            -H 'Content-Type: application/json' \
            -d "{
                \"indices\": \"${indices}\",
                \"ignore_unavailable\": true,
                \"include_global_state\": false
            }"
        
        # Wait for snapshot to complete
        while true; do
            local status=$(curl -s "${ELASTICSEARCH_URL}/_snapshot/backup_repo/${BACKUP_NAME}" | jq -r '.snapshots[0].state')
            if [ "$status" = "SUCCESS" ]; then
                print_success "Elasticsearch backup completed"
                break
            elif [ "$status" = "FAILED" ]; then
                print_error "Elasticsearch backup failed"
                return 1
            fi
            sleep 5
        done
    else
        print_warning "No Elasticsearch indices found to backup"
    fi
}

# Function to backup Docker configurations
backup_docker_config() {
    print_status "Backing up Docker configurations..."
    
    local config_path="${BACKUP_DIR}/${BACKUP_NAME}/config"
    mkdir -p "${config_path}"
    
    # Backup docker-compose.yml
    if [ -f "/opt/honeypot/docker-compose.yml" ]; then
        cp "/opt/honeypot/docker-compose.yml" "${config_path}/"
    fi
    
    # Backup configuration files
    if [ -d "/opt/honeypot/config" ]; then
        cp -r "/opt/honeypot/config" "${config_path}/"
    fi
    
    # Backup environment files
    if [ -f "/opt/honeypot/.env" ]; then
        cp "/opt/honeypot/.env" "${config_path}/"
    fi
    
    print_success "Docker configuration backup completed"
}

# Function to backup system logs
backup_system_logs() {
    print_status "Backing up system logs..."
    
    local logs_path="${BACKUP_DIR}/${BACKUP_NAME}/logs"
    mkdir -p "${logs_path}"
    
    # Backup honeypot logs
    if [ -d "/var/log/honeypot" ]; then
        cp -r "/var/log/honeypot" "${logs_path}/"
    fi
    
    # Backup Docker logs
    sudo docker-compose -f /opt/honeypot/docker-compose.yml logs --no-color > "${logs_path}/docker-compose.log" 2>&1 || true
    
    print_success "System logs backup completed"
}

# Function to create backup metadata
create_backup_metadata() {
    print_status "Creating backup metadata..."
    
    local metadata_file="${BACKUP_DIR}/${BACKUP_NAME}/metadata.json"
    
    cat > "${metadata_file}" << EOF
{
    "backup_name": "${BACKUP_NAME}",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "hostname": "$(hostname)",
    "elasticsearch_version": "$(curl -s ${ELASTICSEARCH_URL} | jq -r '.version.number' 2>/dev/null || echo 'unknown')",
    "docker_version": "$(docker --version | cut -d' ' -f3 | sed 's/,//' 2>/dev/null || echo 'unknown')",
    "backup_size": "$(du -sh ${BACKUP_DIR}/${BACKUP_NAME} | cut -f1)",
    "indices_backed_up": $(curl -s "${ELASTICSEARCH_URL}/_cat/indices/honeypot-*?format=json" | jq '[.[].index]' 2>/dev/null || echo '[]')
}
EOF
    
    print_success "Backup metadata created"
}

# Function to compress backup
compress_backup() {
    print_status "Compressing backup..."
    
    cd "${BACKUP_DIR}"
    tar -czf "${BACKUP_NAME}.tar.gz" "${BACKUP_NAME}/"
    
    if [ $? -eq 0 ]; then
        rm -rf "${BACKUP_NAME}/"
        print_success "Backup compressed: ${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
    else
        print_error "Failed to compress backup"
        return 1
    fi
}

# Function to upload to S3
upload_to_s3() {
    if [ -n "$S3_BUCKET" ]; then
        print_status "Uploading backup to S3..."
        
        aws s3 cp "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz" "s3://${S3_BUCKET}/backups/${BACKUP_NAME}.tar.gz"
        
        if [ $? -eq 0 ]; then
            print_success "Backup uploaded to S3: s3://${S3_BUCKET}/backups/${BACKUP_NAME}.tar.gz"
        else
            print_error "Failed to upload backup to S3"
            return 1
        fi
    else
        print_warning "S3 bucket not configured, skipping upload"
    fi
}

# Function to cleanup old backups
cleanup_old_backups() {
    print_status "Cleaning up old backups..."
    
    # Keep last 7 local backups
    local backup_count=$(ls -1 "${BACKUP_DIR}"/*.tar.gz 2>/dev/null | wc -l)
    if [ "$backup_count" -gt 7 ]; then
        ls -1t "${BACKUP_DIR}"/*.tar.gz | tail -n +8 | xargs rm -f
        print_success "Cleaned up old local backups"
    fi
    
    # Cleanup old S3 backups (keep last 30)
    if [ -n "$S3_BUCKET" ]; then
        aws s3 ls "s3://${S3_BUCKET}/backups/" | sort -k1,2 | head -n -30 | awk '{print $4}' | while read file; do
            if [ -n "$file" ]; then
                aws s3 rm "s3://${S3_BUCKET}/backups/${file}"
            fi
        done
        print_success "Cleaned up old S3 backups"
    fi
}

# Function to verify backup
verify_backup() {
    print_status "Verifying backup..."
    
    local backup_file="${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
    
    if [ -f "$backup_file" ]; then
        # Test archive integrity
        if tar -tzf "$backup_file" >/dev/null 2>&1; then
            local backup_size=$(du -h "$backup_file" | cut -f1)
            print_success "Backup verification passed (Size: $backup_size)"
        else
            print_error "Backup verification failed - archive is corrupted"
            return 1
        fi
    else
        print_error "Backup file not found: $backup_file"
        return 1
    fi
}

# Function to list backups
list_backups() {
    print_status "Available backups:"
    echo
    
    # Local backups
    echo "Local backups:"
    if ls "${BACKUP_DIR}"/*.tar.gz >/dev/null 2>&1; then
        ls -lh "${BACKUP_DIR}"/*.tar.gz | awk '{print $9, $5, $6, $7, $8}'
    else
        echo "No local backups found"
    fi
    echo
    
    # S3 backups
    if [ -n "$S3_BUCKET" ]; then
        echo "S3 backups:"
        aws s3 ls "s3://${S3_BUCKET}/backups/" --human-readable || echo "No S3 backups found"
    fi
}

# Function to restore backup
restore_backup() {
    local backup_name="$1"
    
    if [ -z "$backup_name" ]; then
        print_error "Backup name required for restore"
        return 1
    fi
    
    print_warning "This will restore backup: $backup_name"
    print_warning "Current data will be overwritten!"
    read -p "Are you sure you want to proceed? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Restore cancelled"
        return 0
    fi
    
    print_status "Restoring backup: $backup_name"
    
    # Stop services
    print_status "Stopping services..."
    sudo docker-compose -f /opt/honeypot/docker-compose.yml down
    
    # Extract backup
    local backup_file="${BACKUP_DIR}/${backup_name}.tar.gz"
    if [ ! -f "$backup_file" ]; then
        # Try to download from S3
        if [ -n "$S3_BUCKET" ]; then
            print_status "Downloading backup from S3..."
            aws s3 cp "s3://${S3_BUCKET}/backups/${backup_name}.tar.gz" "$backup_file"
        else
            print_error "Backup file not found: $backup_file"
            return 1
        fi
    fi
    
    # Extract backup
    cd "${BACKUP_DIR}"
    tar -xzf "${backup_name}.tar.gz"
    
    # Restore configurations
    if [ -d "${backup_name}/config" ]; then
        print_status "Restoring configurations..."
        sudo cp -r "${backup_name}/config/"* /opt/honeypot/
    fi
    
    # Start services
    print_status "Starting services..."
    sudo docker-compose -f /opt/honeypot/docker-compose.yml up -d
    
    # Wait for Elasticsearch
    print_status "Waiting for Elasticsearch..."
    for i in {1..30}; do
        if curl -s "${ELASTICSEARCH_URL}/_cluster/health" >/dev/null 2>&1; then
            break
        fi
        sleep 5
    done
    
    # Restore Elasticsearch data
    if [ -d "${backup_name}/elasticsearch" ]; then
        print_status "Restoring Elasticsearch data..."
        
        # Register snapshot repository
        curl -X PUT "${ELASTICSEARCH_URL}/_snapshot/restore_repo" \
            -H 'Content-Type: application/json' \
            -d "{
                \"type\": \"fs\",
                \"settings\": {
                    \"location\": \"${BACKUP_DIR}/${backup_name}/elasticsearch\"
                }
            }"
        
        # Restore snapshot
        curl -X POST "${ELASTICSEARCH_URL}/_snapshot/restore_repo/${backup_name}/_restore" \
            -H 'Content-Type: application/json' \
            -d '{
                "ignore_unavailable": true,
                "include_global_state": false
            }'
    fi
    
    # Cleanup
    rm -rf "${backup_name}/"
    
    print_success "Backup restore completed"
}

# Main function
main() {
    local action="${1:-backup}"
    
    case $action in
        "backup")
            echo "🔄 Starting Honeypot Backup"
            echo "=========================="
            
            create_backup_dir
            backup_elasticsearch
            backup_docker_config
            backup_system_logs
            create_backup_metadata
            compress_backup
            upload_to_s3
            verify_backup
            cleanup_old_backups
            
            print_success "✅ Backup completed successfully: ${BACKUP_NAME}"
            ;;
            
        "list")
            list_backups
            ;;
            
        "restore")
            restore_backup "$2"
            ;;
            
        *)
            echo "Usage: $0 {backup|list|restore} [backup_name]"
            echo
            echo "Commands:"
            echo "  backup           - Create a new backup"
            echo "  list             - List available backups"
            echo "  restore <name>   - Restore from backup"
            echo
            exit 1
            ;;
    esac
}

# Check if running as root for some operations
if [ "$EUID" -eq 0 ]; then
    print_warning "Running as root. Some operations may require sudo."
fi

# Run main function
main "$@"