#!/bin/bash
# =============================================================================
# EC2 User Data Script for Honeypot System
# Automatically installs and configures the honeypot system on AWS EC2
# =============================================================================

set -e

# Variables from Terraform
MAXMIND_ACCOUNT_ID="${maxmind_account_id}"
MAXMIND_LICENSE_KEY="${maxmind_license_key}"
SMTP_HOST="${smtp_host}"
SMTP_USER="${smtp_user}"
SMTP_PASS="${smtp_pass}"
DISCORD_WEBHOOK="${discord_webhook}"
SLACK_WEBHOOK="${slack_webhook}"
S3_BACKUP_BUCKET="${s3_backup_bucket}"
AWS_REGION="${aws_region}"

# System configuration
LOG_FILE="/var/log/honeypot-setup.log"
HONEYPOT_DIR="/opt/honeypot"
HONEYPOT_USER="honeypot"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting honeypot system installation..."

# Update system
log "Updating system packages..."
yum update -y

# Install required packages
log "Installing required packages..."
yum install -y \
    docker \
    git \
    curl \
    wget \
    unzip \
    htop \
    vim \
    awscli \
    python3 \
    python3-pip

# Install Docker Compose
log "Installing Docker Compose..."
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose

# Start and enable Docker
log "Starting Docker service..."
systemctl start docker
systemctl enable docker

# Create honeypot user
log "Creating honeypot user..."
useradd -m -s /bin/bash "$HONEYPOT_USER" || true
usermod -aG docker "$HONEYPOT_USER"

# Create honeypot directory
log "Creating honeypot directory structure..."
mkdir -p "$HONEYPOT_DIR"
chown "$HONEYPOT_USER:$HONEYPOT_USER" "$HONEYPOT_DIR"

# Clone honeypot repository
log "Cloning honeypot repository..."
cd "$HONEYPOT_DIR"
git clone https://github.com/HOAX-116/honeypot-application.git . || {
    log "Failed to clone repository, creating structure manually..."
    mkdir -p honeypots/ssh honeypots/http honeypots/ftp honeypots/telnet
    mkdir -p services/geoip services/alerts services/api services/health
    mkdir -p config/logstash config/kibana config/elasticsearch
    mkdir -p scripts templates
}

# Set up environment file
log "Creating environment configuration..."
cat > "$HONEYPOT_DIR/.env" << EOF
# MaxMind GeoIP Configuration
MAXMIND_ACCOUNT_ID=$MAXMIND_ACCOUNT_ID
MAXMIND_LICENSE_KEY=$MAXMIND_LICENSE_KEY

# Elasticsearch Configuration
ELASTIC_PASSWORD=honeypot_secure_password_$(openssl rand -hex 8)
ELASTIC_USERNAME=elastic

# Alert Configuration
SMTP_HOST=$SMTP_HOST
SMTP_PORT=587
SMTP_USER=$SMTP_USER
SMTP_PASS=$SMTP_PASS

# Discord Webhook
DISCORD_WEBHOOK_URL=$DISCORD_WEBHOOK

# Slack Webhook
SLACK_WEBHOOK_URL=$SLACK_WEBHOOK

# System Configuration
LOG_LEVEL=INFO
HONEYPOT_NETWORK=honeypot_net

# AWS Configuration
AWS_REGION=$AWS_REGION
S3_BACKUP_BUCKET=$S3_BACKUP_BUCKET
EOF

# Set proper permissions
chown "$HONEYPOT_USER:$HONEYPOT_USER" "$HONEYPOT_DIR/.env"
chmod 600 "$HONEYPOT_DIR/.env"

# Configure system limits for Elasticsearch
log "Configuring system limits..."
echo 'vm.max_map_count=262144' >> /etc/sysctl.conf
sysctl -w vm.max_map_count=262144

# Set up log rotation
log "Setting up log rotation..."
cat > /etc/logrotate.d/honeypot << EOF
/var/log/honeypot/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 $HONEYPOT_USER $HONEYPOT_USER
}
EOF

# Create systemd service for honeypot
log "Creating systemd service..."
cat > /etc/systemd/system/honeypot.service << EOF
[Unit]
Description=Honeypot System
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$HONEYPOT_DIR
ExecStart=/usr/local/bin/docker-compose up -d
ExecStop=/usr/local/bin/docker-compose down
TimeoutStartSec=0
User=$HONEYPOT_USER
Group=$HONEYPOT_USER

[Install]
WantedBy=multi-user.target
EOF

# Enable honeypot service
systemctl daemon-reload
systemctl enable honeypot.service

# Set up backup script
log "Creating backup script..."
cat > "$HONEYPOT_DIR/scripts/backup.sh" << 'EOF'
#!/bin/bash
# Backup honeypot data to S3

BACKUP_DIR="/tmp/honeypot-backup-$(date +%Y%m%d-%H%M%S)"
S3_BUCKET="${s3_backup_bucket}"

mkdir -p "$BACKUP_DIR"

# Backup Elasticsearch data
docker exec elasticsearch curl -X POST "localhost:9200/_snapshot/backup/snapshot_$(date +%Y%m%d_%H%M%S)?wait_for_completion=true"

# Backup configuration files
cp -r /opt/honeypot/config "$BACKUP_DIR/"
cp /opt/honeypot/.env "$BACKUP_DIR/"

# Create archive
tar -czf "$BACKUP_DIR.tar.gz" -C "$(dirname "$BACKUP_DIR")" "$(basename "$BACKUP_DIR")"

# Upload to S3
aws s3 cp "$BACKUP_DIR.tar.gz" "s3://$S3_BUCKET/backups/"

# Cleanup
rm -rf "$BACKUP_DIR" "$BACKUP_DIR.tar.gz"
EOF

chmod +x "$HONEYPOT_DIR/scripts/backup.sh"
chown "$HONEYPOT_USER:$HONEYPOT_USER" "$HONEYPOT_DIR/scripts/backup.sh"

# Set up daily backup cron job
echo "0 2 * * * $HONEYPOT_USER $HONEYPOT_DIR/scripts/backup.sh" >> /etc/crontab

# Create health check script
log "Creating health check script..."
cat > "$HONEYPOT_DIR/scripts/health-check.sh" << 'EOF'
#!/bin/bash
# Health check script for honeypot system

SERVICES=("elasticsearch" "logstash" "kibana" "ssh-honeypot" "http-honeypot" "ftp-honeypot" "telnet-honeypot")
FAILED_SERVICES=()

echo "Checking honeypot system health..."

for service in "$${SERVICES[@]}"; do
    if ! docker ps | grep -q "$service"; then
        FAILED_SERVICES+=("$service")
    fi
done

if [ $${#FAILED_SERVICES[@]} -eq 0 ]; then
    echo "✅ All services are running"
    exit 0
else
    echo "❌ Failed services: $${FAILED_SERVICES[*]}"
    exit 1
fi
EOF

chmod +x "$HONEYPOT_DIR/scripts/health-check.sh"
chown "$HONEYPOT_USER:$HONEYPOT_USER" "$HONEYPOT_DIR/scripts/health-check.sh"

# Install CloudWatch agent
log "Installing CloudWatch agent..."
wget https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm
rpm -U ./amazon-cloudwatch-agent.rpm

# Configure CloudWatch agent
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << EOF
{
    "logs": {
        "logs_collected": {
            "files": {
                "collect_list": [
                    {
                        "file_path": "/var/log/honeypot-setup.log",
                        "log_group_name": "/aws/ec2/honeypot-system",
                        "log_stream_name": "setup"
                    },
                    {
                        "file_path": "/var/log/honeypot/*.log",
                        "log_group_name": "/aws/ec2/honeypot-system",
                        "log_stream_name": "honeypot"
                    }
                ]
            }
        }
    },
    "metrics": {
        "namespace": "HoneypotSystem",
        "metrics_collected": {
            "cpu": {
                "measurement": ["cpu_usage_idle", "cpu_usage_iowait", "cpu_usage_user", "cpu_usage_system"],
                "metrics_collection_interval": 60
            },
            "disk": {
                "measurement": ["used_percent"],
                "metrics_collection_interval": 60,
                "resources": ["*"]
            },
            "mem": {
                "measurement": ["mem_used_percent"],
                "metrics_collection_interval": 60
            }
        }
    }
}
EOF

# Start CloudWatch agent
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s

# Change ownership of honeypot directory
chown -R "$HONEYPOT_USER:$HONEYPOT_USER" "$HONEYPOT_DIR"

# Start honeypot system
log "Starting honeypot system..."
cd "$HONEYPOT_DIR"
sudo -u "$HONEYPOT_USER" docker-compose up -d

# Wait for services to be ready
log "Waiting for services to start..."
sleep 60

# Verify services are running
log "Verifying services..."
sudo -u "$HONEYPOT_USER" "$HONEYPOT_DIR/scripts/health-check.sh"

# Create completion marker
touch /tmp/honeypot-setup-complete

log "Honeypot system installation completed successfully!"
log "Access Kibana at: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):5601"
log "API Gateway at: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):8000"

# Send notification if webhook is configured
if [ -n "$DISCORD_WEBHOOK" ]; then
    curl -H "Content-Type: application/json" \
         -X POST \
         -d "{\"content\":\"🍯 Honeypot system deployed successfully on $(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)\"}" \
         "$DISCORD_WEBHOOK" || true
fi

exit 0